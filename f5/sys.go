package f5

import (
	"encoding/json"
	"fmt"
	"github.com/mitchellh/mapstructure"
)

/*******
 * CPU *
 *******/

// represents statistics for a single CPU core
type LBCPUSocketCoreStat struct {
	CpuId              LBStatsValue `json:"cpuId"`
	FiveMinAvgIdle     LBStatsValue `json:"fiveMinAvgIdle"`
	FiveMinAvgIowait   LBStatsValue `json:"fiveMinAvgIowait"`
	FiveMinAvgIrq      LBStatsValue `json:"fiveMinAvgIrq"`
	FiveMinAvgNiced    LBStatsValue `json:"fiveMinAvgNiced"`
	FiveMinAvgSoftirq  LBStatsValue `json:"fiveMinAvgSoftirq"`
	FiveMinAvgStolen   LBStatsValue `json:"fiveMinAvgStolen"`
	FiveMinAvgSystem   LBStatsValue `json:"fiveMinAvgSystem"`
	FiveMinAvgUser     LBStatsValue `json:"fiveMinAvgUser"`
	FiveSecAvgIdle     LBStatsValue `json:"fiveSecAvgIdle"`
	FiveSecAvgIowait   LBStatsValue `json:"fiveSecAvgIowait"`
	FiveSecAvgIrq      LBStatsValue `json:"fiveSecAvgIrq"`
	FiveSecAvgNiced    LBStatsValue `json:"fiveSecAvgNiced"`
	FiveSecAvgRatio    LBStatsValue `json:"fiveSecAvgRatio"`
	FiveSecAvgSoftirq  LBStatsValue `json:"fiveSecAvgSoftirq"`
	FiveSecAvgStolen   LBStatsValue `json:"fiveSecAvgStolen"`
	FiveSecAvgSystem   LBStatsValue `json:"fiveSecAvgSystem"`
	FiveSecAvgUser     LBStatsValue `json:"fiveSecAvgUser"`
	Idle               LBStatsValue `json:"idle"`
	Iowait             LBStatsValue `json:"iowait"`
	Irq                LBStatsValue `json:"irq"`
	Niced              LBStatsValue `json:"niced"`
	OneMinAvgIdle      LBStatsValue `json:"oneMinAvgIdle"`
	OneMinAvgIowait    LBStatsValue `json:"oneMinAvgIowait"`
	OneMinAvgIrq       LBStatsValue `json:"oneMinAvgIrq"`
	OneMinAvgNiced     LBStatsValue `json:"oneMinAvgNiced"`
	OneMinAvgSoftirq   LBStatsValue `json:"oneMinAvgSoftirq"`
	OneMinAvgStolen    LBStatsValue `json:"oneMinAvgStolen"`
	OneMinAvgSystem    LBStatsValue `json:"oneMinAvgSystem"`
	OneMinAvgUser      LBStatsValue `json:"oneMinAvgUser"`
	Softirq            LBStatsValue `json:"softirq"`
	Stolen             LBStatsValue `json:"stolen"`
	System             LBStatsValue `json:"system"`
	User               LBStatsValue `json:"user"`
}

// container for cores
type LBCPUSocket struct {
	Kind      string                 `json:"kind"`
	SelfLink  string                 `json:"selfLink"`
	Cores     []LBCPUSocketCoreStat  `json:"cores"`
}

// CPUSummary contains a summary of all CPU stats.
type LBCPUSummary struct {
	Kind       string         `json:"kind"`
	SelfLink   string         `json:"selfLink"`
	Sockets    []LBCPUSocket  `json:"sockets"`
}

func extractCpuSocket(data map[string]interface{}) LBCPUSocket {
	var socket LBCPUSocket

	if nestedStats, ok := data["nestedStats"].(map[string]interface{}); ok {
	    if kind, ok := nestedStats["kind"].(string); ok {
	        json.Unmarshal([]byte(kind), &socket.Kind)
	    }
	    if selfLink, ok := nestedStats["selfLink"].(string); ok {
	        json.Unmarshal([]byte(selfLink), &socket.SelfLink)
	    }

		if entries, ok := nestedStats["entries"].(map[string]interface{}); ok {

			// entries is an object with one key, representing the cpu socket
			for _, v := range entries {

				if entry, ok := v.(map[string]interface{}); ok {

					if nestedCpuStats, ok := entry["nestedStats"].(map[string]interface{}); ok {

						if coreEntries, ok := nestedCpuStats["entries"].(map[string]interface{}); ok {

							for _, coreEntry := range coreEntries {
						        if core, ok := coreEntry.(map[string]interface{}); ok {
						            if nestedCoreStats, ok := core["nestedStats"].(map[string]interface{}); ok {

										if coreEntries, ok := nestedCoreStats["entries"].(map[string]interface{}); ok {

											var socketCoreStat LBCPUSocketCoreStat
											if err := mapstructure.Decode(coreEntries, &socketCoreStat); err == nil {
												//socketCoreStatBytes, _ := json.Marshal(socketCoreStat)
												//fmt.Printf("  Core: %s\n", string(socketCoreStatBytes))
												socket.Cores = append(socket.Cores, socketCoreStat)
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return socket
}

// ShowCPUStats retrieves CPU statistics from the F5 device.
func (f *Device) ShowCPUStats() (error, *LBCPUSummary) {
	url := f.Proto + "://" + f.Hostname + "/mgmt/tm/sys/cpu"
	var res map[string]json.RawMessage
	err, _ := f.sendRequest(url, GET, nil, &res)
	if err != nil {
		return err, nil
	}

	cpuStats := LBCPUSummary{}

	var socketEntries map[string]interface{}
	if err := json.Unmarshal(res["entries"], &socketEntries); err != nil {
	    return fmt.Errorf("error unmarshaling entries: %w", err), nil
	}

	var sockets []LBCPUSocket
	for _, v := range socketEntries {
		if socketEntry, ok := v.(map[string]interface{}); ok {
			socket := extractCpuSocket(socketEntry)
			//socketBytes, _ := json.Marshal(socket)
			//fmt.Printf("Socket: %s\n", string(socketBytes))
			//fmt.Printf("Kind: %s, SelfLink: %s\n", socket.Kind, socket.SelfLink)
			sockets = append(sockets, socket)
		}

		if err := json.Unmarshal(res["kind"], &cpuStats.Kind); err != nil {
			fmt.Println("Error unmarshalling 'kind':", err)
			return err, nil;
		}
		if err := json.Unmarshal(res["selfLink"], &cpuStats.SelfLink); err != nil {
			fmt.Println("Error unmarshalling 'selfLink':", err)
			return err, nil;
		}

		cpuStats.Sockets = sockets
		//fmt.Printf("kind = %s\n", cpuStats.Kind)
	}

	return nil, &cpuStats
}


