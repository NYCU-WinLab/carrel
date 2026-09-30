# Carrel 0.3：作業恢復、就緒檢查與資源保留

本次處理六項可靠性問題；備份與多節點不在範圍內。

| 問題 | 現在的行為 |
|---|---|
| 建機占住 MCP request | 立即回傳持久化 operation；查詢不等待基礎設施 writer，使用 `operation_get` 追蹤 |
| 多資源部署失敗後殘留 | `deployment_apply` 先一次保留全組配額；預設只回收這次建立的資源，可選 `keep`；失敗清理仍占額度並可重試 |
| SSH 通了就宣稱可用 | 新 VM 必須完成 cloud-init、managed 私網設定及指定的應用檢查；沒有指定應用檢查會回傳 `not_checked` |
| 私網需要手設 IP | managed 模式提供固定 DHCP IP、MTU 1450，保留原預設路由與 DNS；`raw_l2` 留給自行管理位址的實驗 |
| 停機讓出 CPU／RAM | 配置期間持續保留；刪除或停機縮減規格，須等 hypervisor 確認後才釋放 |
| 快照共用磁碟額度且還原後停機 | 獨立 `snapshot_gb` 最壞情況預留量，加上實測 retained blocks；還原恢復原電源狀態，原先運行的 VM 重新檢查就緒 |

## 操作範例

兩台 VM 加私網：先用相同規格呼叫 `deployment_plan`，通過後呼叫 `deployment_apply`，帶穩定的 `idempotency_key`。取得 `queued` 只代表受理，尚未保留容量；依 `poll_after_seconds` 查 `operation_get`，直到終態再看 `result` 或 `error`。

指定作業 ID 的 `operation_get` 預設最多等待 20 秒，完成就提早回傳；`wait_seconds=0` 可立即查狀態。這個等待不持有 writer lock，其他查詢與作業提交仍可進行。

例如 nginx 可用性指定 `health_checks: [{"type":"http","port":80,"path":"/","status":200}]`，或 `[{"type":"service","service":"nginx"}]`。HTTP／TCP 檢查只連 VM 內的 `127.0.0.1`。需要外部 HTTP／HTTPS 時，仍須配置 port／domain。

若 `cleanup_failed`，先 `operation_retry` 完成清理，直到 `rolled_back`；想重新部署再 retry 一次。`on_failure=keep` 留下原配置，修復後 retry 沿用同一組資源。相同 idempotency key 與參數不會重複建立。重試也會核對原配置身分，避免 VMID 或網卡編號重用後誤操作新資源。

## 限制

基礎設施 mutation 目前由單一 writer 依序執行，包含等待 guest 就緒；查詢和提交作業不等待它。這次沒有實作並行建機或多節點排程。租戶額度是上限，不保證未建立機器的容量；vCPU 仍是共享 CPU。

`snapshot_gb` 代表保守預留量，與實際占用分開呈現；實際額外區塊採 snapshot 與 live mappings 的聯集扣除 live mappings，同租戶共用區塊只算一次。實測值帶取樣時間；取樣失敗不釋放預留。快照仍是磁碟快照，還原可能短暫中斷服務。

舊 VM 若沒有固定 guest reporter／managed 網卡設定，不能直接使用自動私網；可用 raw L2 或建立新 VM。CT 的位址由 PVE 設定，沒有 VM 的 cloud-init／應用檢查介面。

## 驗證方式與修正

自動化測試涵蓋非阻塞查詢、持久化作業與重試、全組資源保留、失敗回收／保留、清理失敗仍計配額、ID 重用保護、停機資源保留、縮減成功後釋放、快照配額與共用區塊計算、guest report 的 token／來源 IP、初始化失敗，以及 managed／raw 網路界線。

實機驗收使用兩個臨時 Keycloak 成員帳號、獨立測試租戶與臨時 SSH key，沒有修改一般使用者或專案的 VM。首次兩台 Ubuntu 的測試抓到 systemd-networkd 不接受 MAC 通配字元、guest report 被基礎設施防火牆擋住；已改成明確 MAC 清單並放行指定的內部回報端點。這兩台當時經手動修補，不能當成全新映像驗收，後續另建全新 VM／CT 重測。

私網刪除測試抓到 namespace 移除與 veth 刪除的競態，已調整順序，並回收未完成建立留下的 namespace／lease。建機中重啟測試另抓到 systemd 同時終止 SSH 子程序，使作業被誤判失敗；服務改用 `KillMode=mixed`，讓主程序先保留未完成作業再停止子程序。部分 clone 的清理也必須核對節點 manifest 與 VM description 的同一配置標記，不能僅憑 VMID 刪除。

原生 Codex 測試沿用 `gpt-6-astra`、`github_copilot`、`xhigh`，在空白 workspace 使用臨時帳號，限定 Carrel MCP。第一輪規劃將 HTTP 檢查錯寫為 URL；補上工具範例及欄位驗證診斷後，相同 prompt 重測從 5 次呼叫／1 次拒絕，改善為 4 次呼叫／0 次拒絕。模型正確區分預演與真正的開機、套件和連線驗證。每個 prompt 只重測一次，不能推論跨模型成功率；耗時亦受其他驗收工作影響。

另一個 prompt 實際建立 managed 網路、等待成功、查 DHCP 設定，再刪除並等待成功。Codex 正確使用預演、穩定的 idempotency key 與 operation 查詢，沒有把 queued 當成功。加入等待參數後，同一 prompt 使用 10 次工具呼叫，先前為 16 次；兩次都成功，沒有 shell／SSH／其他 MCP。耗時分別為 113.0 與 147.0 秒，兩次主機排隊負載不同，不作效能基準。

## 最終實機結果

- 全新 Ubuntu 24.04 VM、Debian 13 VM 與 Debian 13 CT 的部署，在建立第二台 VM 時重啟控制服務，原 operation 自動恢復並成功，同一組 VMID 沒有重複配置。
- 全新 Ubuntu 與 CT 直接透過自動私網互通；Debian 開機後熱加 managed NIC，自動取得 IP 並互通，原預設路由保留。這一輪沒有手動修補客體。
- 停機後從 2 vCPU／2 GiB 縮減至 1 vCPU／1 GiB，確認配額釋放 1 vCPU／1 GiB，再啟動成功。另測停機但不縮規格時，主機 CPU／RAM committed 不變。
- 兩台各 12 GiB VM 加一份快照，配額分開顯示 `disk_gb=24`、`snapshot_gb=12`；覆寫檔案後量到額外保留區塊。還原後原檔案內容、SSH、nginx 及對外 HTTP 恢復，原運行 VM 自動開機。
- `runcmd: [["false"]]` 的 VM 即使 SSH 已開，也回報 `guest_not_ready` 與 `failed_step=0`。跨租戶讀取配額及作業遭拒，其他租戶看不到其機器。

最終自動測試 **83 項通過**，Ruff、Python 編譯及 whitespace checks 通過。部署使用 0.3.0，保留回復副本。可核對的測試結果、Codex prompts／工具呼叫及部署雜湊見 [驗收資料](2026-10-01-reliability-results.json)。

建機期間 72 次 `whoami` 查詢中位數為 0.15 秒，最慢 4.337 秒。最後核對 installed package、service source 與三個 node helper 的 SHA-256 均與本機一致，公開 health 回報 0.3.0。測試 VM／CT、磁碟、快照、公開 port、私網、DHCP namespace／lease、臨時 Keycloak 帳號、OAuth client 與本機憑證已清除；保留停用的租戶序號及正常稽核。`zyx1121` 與 `iii-edge-ai` 的配置用量仍為零，既有 VM190 保持運行。
