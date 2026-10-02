use reqwest::blocking::Client;
use serde_json::{Map, Value, json};
use std::{env, fs, process::Command, time::Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Http {
    client: Client,
    base: String,
    authorization: String,
}

fn cli(path: &str) -> Result<Value> {
    let output = Command::new("pvesh")
        .args(["get", path, "--output-format", "json"])
        .output()?;
    if !output.status.success() {
        return Err("pvesh read failed".into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn get(http: Option<&Http>, path: &str) -> Result<Value> {
    match http {
        None => cli(path),
        Some(h) => {
            let response = h
                .client
                .get(format!("{}/api2/json{}", h.base, path))
                .header("Authorization", &h.authorization)
                .send()
                .map_err(|_| "HTTP request failed")?;
            if !response.status().is_success() {
                return Err(format!("HTTP status {}", response.status()).into());
            }
            let body: Value = serde_json::from_slice(&response.bytes()?)?;
            body.get("data")
                .cloned()
                .ok_or_else(|| "missing API data".into())
        }
    }
}

fn observe(http: Option<&Http>, workload: &str) -> Result<Value> {
    if workload == "inventory" {
        Ok(json!({
            "volumes": get(http, "/nodes/carrel01/storage/local-lvm/content")?,
            "resources": get(http, "/cluster/resources")?,
            "storage": get(http, "/nodes/carrel01/storage/local-lvm/status")?,
            "status": get(http, "/nodes/carrel01/status")?,
        }))
    } else if workload == "topology" {
        let vnets = get(http, "/cluster/sdn/vnets")?;
        let names: Vec<String> = vnets
            .as_array()
            .ok_or("missing VNet array")?
            .iter()
            .filter_map(|v| v.get("vnet")?.as_str())
            .filter(|v| {
                v.len() == 4 && v.starts_with('t') && v[1..].bytes().all(|b| b.is_ascii_digit())
            })
            .map(str::to_owned)
            .collect();
        let mut subnets = Map::new();
        if http.is_some() {
            for name in names {
                let value = get(http, &format!("/cluster/sdn/vnets/{name}/subnets"))?;
                subnets.insert(name, value);
            }
        } else {
            // Match the legacy Python adapter's four concurrent subnet CLI reads.
            for chunk in names.chunks(4) {
                let results = std::thread::scope(|scope| {
                    let handles: Vec<_> = chunk
                        .iter()
                        .map(|name| {
                            scope.spawn(move || {
                                cli(&format!("/cluster/sdn/vnets/{name}/subnets"))
                                    .map_err(|e| e.to_string())
                            })
                        })
                        .collect();
                    handles
                        .into_iter()
                        .map(|h| h.join().expect("read thread"))
                        .collect::<Vec<_>>()
                });
                for (name, value) in chunk.iter().zip(results) {
                    subnets.insert(name.clone(), value.map_err(|e| format!("CLI read: {e}"))?);
                }
            }
        }
        Ok(json!({"vnets": vnets, "subnets": subnets}))
    } else {
        Err("unknown workload".into())
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 || !["http", "pvesh"].contains(&args[1].as_str()) {
        return Err("expected http|pvesh inventory|topology count config-path".into());
    }
    let count: usize = args[3].parse()?;
    if !(1..=100).contains(&count) {
        return Err("invalid count".into());
    }
    let http = if args[1] == "http" {
        let config: Value = serde_json::from_slice(&fs::read(&args[4])?)?;
        let ca = fs::read(config["ca"].as_str().ok_or("missing CA")?)?;
        Some(Http {
            client: Client::builder()
                .no_proxy()
                .http1_only()
                .tcp_nodelay(true)
                .tls_built_in_root_certs(false)
                .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
            base: config["base"].as_str().ok_or("missing base")?.to_owned(),
            authorization: config["authorization"]
                .as_str()
                .ok_or("missing authorization")?
                .to_owned(),
        })
    } else {
        None
    };
    let mut samples = Vec::new();
    let mut result = Value::Null;
    for _ in 0..count {
        let start = Instant::now();
        result = observe(http.as_ref(), &args[2])?;
        samples.push(start.elapsed().as_secs_f64());
    }
    println!("{}", json!({"samples": samples, "result": result}));
    Ok(())
}
