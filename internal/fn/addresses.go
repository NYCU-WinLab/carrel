package fn

// A function may reach the internet and public names, and nothing else
// (PLAN 7.11). Every address below is dropped twice: once in the instance's
// own network namespace, and once on the function host.
var blocked = []string{
	"0.0.0.0/8",      // this network
	"10.0.0.0/8",     // private: tenant networks, the platform, the function host
	"100.64.0.0/10",  // carrier NAT and tailnets
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // link local, where metadata services live
	"172.16.0.0/12",  // private, and every guest's own link
	"192.168.0.0/16", // private: the nodes' management network
	"224.0.0.0/3",    // multicast, reserved and broadcast
}
