package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	blacklist      = make(map[uint32]bool)
	internalRanges = []struct {
		start uint32
		end   uint32
	}{
		{ipToInt("10.0.0.0"), ipToInt("10.255.255.255")},
		{ipToInt("172.16.0.0"), ipToInt("172.31.255.255")},
		{ipToInt("192.168.0.0"), ipToInt("192.168.255.255")},
		{ipToInt("127.0.0.0"), ipToInt("127.255.255.255")},
		{ipToInt("169.254.0.0"), ipToInt("169.254.255.255")},
		{ipToInt("224.0.0.0"), ipToInt("239.255.255.255")},
		{ipToInt("240.0.0.0"), ipToInt("255.255.255.255")},
	}
	scanCount     uint64
	openCount     uint64
	totalScanners int32  
	quietMode     bool
	maxWorkers    int32 = 5000  
)

func ipToInt(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	if ip == nil || len(ip) < 4 {
		return 0
	}
	if ip4 := ip.To4(); ip4 != nil {
		return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
	}
	return 0
}

func intToIP(ipInt uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ipInt>>24)&0xFF,
		(ipInt>>16)&0xFF,
		(ipInt>>8)&0xFF,
		ipInt&0xFF)
}

func isInternalIP(ipInt uint32) bool {
	for _, r := range internalRanges {
		if ipInt >= r.start && ipInt <= r.end {
			return true
		}
	}
	return false
}

type IPGenerator struct {
	multiplier uint32
	prime      uint32
	current    uint32
	mutex      sync.Mutex
}

func NewIPGenerator() *IPGenerator {
	
	prime := uint32(4294967291)
	
	
	rand.Seed(time.Now().UnixNano())
	mult := uint32(rand.Intn(0x7FFFFFFF) + 2)
	
	
	start := uint32(rand.Intn(0x7FFFFFFF))
	
	return &IPGenerator{
		multiplier: mult,
		prime:      prime,
		current:    start,
	}
}

func (g *IPGenerator) Next() uint32 {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	
	for {
	
		g.current = (g.current * g.multiplier) % g.prime
		
		// dính list không scan burh
		if blacklist[g.current] || isInternalIP(g.current) || g.current == 0 || g.current == 0xFFFFFFFF {
			continue
		}
		
		return g.current
	}
}


func fastConnect(ipInt uint32, port int, results chan<- string, timeout time.Duration) {
	ipStr := intToIP(ipInt)
	
	atomic.AddUint64(&scanCount, 1)
	
	
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	
	d := net.Dialer{
		Timeout:   timeout,
		KeepAlive: -1,
	}
	
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ipStr, port))
	
	if err == nil {
		conn.Close()
		atomic.AddUint64(&openCount, 1)
		results <- ipStr
	}
}

func generateIPs(ipGen *IPGenerator, ipChan chan uint32, batchSize int, done <-chan bool) {
	for {
		select {
		case <-done:
			return
		default:
			batch := make([]uint32, 0, batchSize)
			
			
			for i := 0; i < batchSize; i++ {
				batch = append(batch, ipGen.Next())
			}
			
			
			rand.Shuffle(len(batch), func(i, j int) {
				batch[i], batch[j] = batch[j], batch[i]
			})
			
			
			for _, ip := range batch {
				select {
				case ipChan <- ip:
					
				case <-done:
					return
				default:
					
					time.Sleep(1 * time.Millisecond)
					select {
					case ipChan <- ip:
					case <-done:
						return
					}
				}
			}
		}
	}
}


func scanWorker(ipChan <-chan uint32, port int, results chan<- string, wg *sync.WaitGroup, timeout time.Duration, done <-chan bool) {
	defer wg.Done()
	
	for {
		select {
		case <-done:
			return
		case ipInt, ok := <-ipChan:
			if !ok {
				return
			}
			fastConnect(ipInt, port, results, timeout)
		}
	}
}


func statusPrinter(startTime time.Time, targetRate int, done <-chan bool) {
	if quietMode {
		return
	}
	
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	var lastCount uint64
	lastTime := time.Now()
	
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			elapsed := now.Sub(lastTime).Seconds()
			totalElapsed := time.Since(startTime).Seconds()
			
			if elapsed < 0.1 {
				continue
			}
			
			currentCount := atomic.LoadUint64(&scanCount)
			opened := atomic.LoadUint64(&openCount)
			workers := atomic.LoadInt32(&totalScanners)
			
			
			recentRate := float64(currentCount - lastCount) / elapsed
			overallRate := float64(currentCount) / totalElapsed
			
			fmt.Fprintf(os.Stderr, "\r[%s] Scanned: %d | Open: %d | Current Rate: %.2f ips/sec | Avg Rate: %.2f | Target: %d ips/sec | Workers: %d", 
				time.Since(startTime).Round(time.Second), currentCount, opened, recentRate, overallRate, targetRate, workers)
			
			lastCount = currentCount
			lastTime = now
			
		case <-done:
			return
		}
	}
}


func loadTargetsFromFile(filename string) ([]uint32, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	var targets []uint32
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		
		if strings.Contains(line, "/") {
			ip, ipnet, err := net.ParseCIDR(line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Invalid CIDR %s: %v\n", line, err)
				continue
			}
			
			
			startIP := ipToInt(ip.String()) & ipToInt(net.IP(ipnet.Mask).String())
			
		
			ones, bits := ipnet.Mask.Size()
			count := 1 << uint(bits-ones)
			
			// Limit large CIDR blocks to prevent memory issues
			// if count > 65536 {
		
			// 	rangeIPs := make([]uint32, 65536)
				
			
			// 	for i := uint32(0); i < 65536; i++ {
			// 		rangeIPs[i] = startIP + uint32(rand.Intn(count))
			// 	}
				
			// 	targets = append(targets, rangeIPs...)
			// } else {
			
				rangeIPs := make([]uint32, count)
				for i := uint32(0); i < uint32(count); i++ {
					rangeIPs[i] = startIP + i
				}
				
				
				rand.Shuffle(len(rangeIPs), func(i, j int) {
					rangeIPs[i], rangeIPs[j] = rangeIPs[j], rangeIPs[i]
				})
				
				targets = append(targets, rangeIPs...)
			
		} else {
		
			targets = append(targets, ipToInt(line))
		}
	}
	

	rand.Shuffle(len(targets), func(i, j int) {
		targets[i], targets[j] = targets[j], targets[i]
	})
	
	return targets, scanner.Err()
}


func loadTargetsFromStdin() ([]uint32, error) {
	var targets []uint32
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		if strings.Contains(line, "/") {
			
			ip, ipnet, err := net.ParseCIDR(line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Invalid CIDR %s: %v\n", line, err)
				continue
			}
			
			
			startIP := ipToInt(ip.String()) & ipToInt(net.IP(ipnet.Mask).String())
			
			
			ones, bits := ipnet.Mask.Size()
			count := 1 << uint(bits-ones)
			
			
			// if count > 65536 {
			// 	fmt.Fprintf(os.Stderr, "Warning: Large CIDR block %s with %d IPs limited to 65536 randomized IPs\n", line, count)
			// 	rangeIPs := make([]uint32, 65536)
				
				
			// 	for i := uint32(0); i < 65536; i++ {
			// 		rangeIPs[i] = startIP + uint32(rand.Intn(count))
			// 	}
				
			// 	targets = append(targets, rangeIPs...)
			// } else {
				
				rangeIPs := make([]uint32, count)
				for i := uint32(0); i < uint32(count); i++ {
					rangeIPs[i] = startIP + i
				}
				rand.Shuffle(len(rangeIPs), func(i, j int) {
					rangeIPs[i], rangeIPs[j] = rangeIPs[j], rangeIPs[i]
				})
				
				targets = append(targets, rangeIPs...)
			// }
		} else {
			
			targets = append(targets, ipToInt(line))
		}
	}
	
	
	rand.Shuffle(len(targets), func(i, j int) {
		targets[i], targets[j] = targets[j], targets[i]
	})
	
	return targets, scanner.Err()
}


func dynamicWorkerAdjuster(targetRate *int, workerControl chan<- int, rateChan <-chan float64, done <-chan bool) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	
	targetRateFloat := float64(*targetRate)
	minRate := targetRateFloat * 0.8
	maxRate := targetRateFloat * 1.2
	
	
	lastAdjust := time.Now()
	currentRate := 0.0
	
	for {
		select {
		case rate := <-rateChan:
			currentRate = rate
			
		case <-ticker.C:
			now := time.Now()
			
			if now.Sub(lastAdjust) < 2*time.Second {
				continue
			}
			
			workers := atomic.LoadInt32(&totalScanners)
			
			if currentRate < minRate {
				
				if currentRate < minRate*0.5 {
					
					delta := int(float64(workers) * 0.3)
					if delta < 50 {
						delta = 50
					}
					if delta > 500 {
						delta = 500
					}
					
				
					if int(workers) + delta > int(maxWorkers) {
						delta = int(maxWorkers) - int(workers)
					}
					
					if delta > 0 {
						workerControl <- delta
						lastAdjust = now
					}
				} else {
					
					delta := int(float64(workers) * 0.15)
					if delta < 20 {
						delta = 20
					}
					if delta > 200 {
						delta = 200
					}
					
					
					if int(workers) + delta > int(maxWorkers) {
						delta = int(maxWorkers) - int(workers)
					}
					
					if delta > 0 {
						workerControl <- delta
						lastAdjust = now
					}
				}
			} else if currentRate > maxRate && workers > 100 {
				
				delta := -int(float64(workers) * 0.1)
				if delta > -10 {
					delta = -10
				}
				if delta < -200 {
					delta = -200
				}
				
				
				minWorkers := int32(100)
				if workers + int32(delta) < minWorkers {
					delta = int(minWorkers - workers)
				}
				
				if delta < 0 {
					workerControl <- delta
					lastAdjust = now
				}
			}
			
		case <-done:
			return
		}
	}
}


func hasStdinInput() bool {
	stat, _ := os.Stdin.Stat()
	return (stat.Mode() & os.ModeCharDevice) == 0
}

func main() {
	
	port := flag.Int("p", 22, "Port Cần scan mặch định 80")
	targetFile := flag.String("w", "", "file chứa list cần scan ")
	blacklistFile := flag.String("b", "", "danh sách list cần block")
	scanRateFlag := flag.Int("B", 2000, "rate /s")
	outputFile := flag.String("o", "", "file out")
	quietModeFlag := flag.Bool("q", false, "như -q của zmap")
	durationFlag := flag.Int("d", 24 * 60, "thời gian scan")
	timeoutFlag := flag.Int("t", 2, "timeout check mạc định 2s")
	stdinFlag := flag.Bool("stdin", false, "Bật Cờ stdin ( viết tool đọc nhưu zmap )")
	maxWorkersFlag := flag.Int("wr", 5000, "số max (nhiều quá bị die lock chưa fix được)workers")
	minRateFlag := flag.Int("min-rate", 1000, "tối thiểu rate")
	
	flag.Parse()
	
	
	maxWorkers = int32(*maxWorkersFlag)
	if maxWorkers < 100 {
		maxWorkers = 100
	} else if maxWorkers > 10000 {
		maxWorkers = 10000 
	}
	
	// xem có cờ | (tool chạy đằng sau không có thì bật flag đó = true như zmap)
	stdinInput := *stdinFlag || hasStdinInput()
	
	
	quietMode = *quietModeFlag
	
	
	rand.Seed(time.Now().UnixNano())
	
	
	targetRate := *scanRateFlag
	minRate := *minRateFlag
	
	if targetRate < minRate {
		targetRate = minRate
	}
	if targetRate > 10000 {
		targetRate = 10000
	}
	
	
	var outWriter *bufio.Writer
	if *outputFile != "" {
		outFile, err := os.Create(*outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer outFile.Close()
		outWriter = bufio.NewWriter(outFile)
		defer outWriter.Flush()
	}
	

	if *blacklistFile != "" {
		file, err := os.Open(*blacklistFile)
		if err == nil {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				ip := strings.TrimSpace(scanner.Text())
				if ip != "" && !strings.HasPrefix(ip, "#") {
					blacklist[ipToInt(ip)] = true
				}
			}
			file.Close()
			if !quietMode {
				fmt.Fprintf(os.Stderr, "Loaded %d blacklisted IPs\n", len(blacklist))
			}
		}
	}
	

	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)

	initialWorkers := targetRate / 20
	

	if initialWorkers < numCPU*10 {
		initialWorkers = numCPU * 10
	}
	
	if initialWorkers > int(maxWorkers/2) {
		initialWorkers = int(maxWorkers / 2)
	}
	

	atomic.StoreInt32(&totalScanners, int32(initialWorkers))
	
	if !quietMode {
		fmt.Fprintf(os.Stderr, "KamiMap: Scanning port %d at target rate %d/s (min: %d/s) using %d initial workers (max: %d)\n", 
			*port, targetRate, minRate, initialWorkers, maxWorkers)
	}
	

	resultChan := make(chan string, targetRate)
	ipChan := make(chan uint32, targetRate*3)
	workerControl := make(chan int, 100)
	rateChan := make(chan float64, 10)
	

	statusDone := make(chan bool)
	workerDone := make(chan bool)
	generatorDone := make(chan bool)
	

	go func() {
		for result := range resultChan {
		
			fmt.Println(result)
			
		
			if outWriter != nil {
				outWriter.WriteString(result + "\n")
				
				if atomic.LoadUint64(&openCount) % 100 == 0 {
					outWriter.Flush()
				}
			}
		}
	}()
	

	var scanTargets []uint32
	var err error
	
	if stdinInput {
		scanTargets, err = loadTargetsFromStdin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading targets from stdin: %v\n", err)
			os.Exit(1)
		}
		if !quietMode && len(scanTargets) > 0 {
			fmt.Fprintf(os.Stderr, "Loaded %d target IPs from stdin\n", len(scanTargets))
		}
	} else if *targetFile != "" {
		scanTargets, err = loadTargetsFromFile(*targetFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading targets: %v\n", err)
			os.Exit(1)
		}
		if !quietMode {
			fmt.Fprintf(os.Stderr, "Loaded %d target IPs from file\n", len(scanTargets))
		}
	}


	startTime := time.Now()

	go func() {
		if quietMode {
			return
		}
		
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		
		var lastCount uint64
		lastTime := time.Now()
		
		for {
			select {
			case <-ticker.C:
				now := time.Now()
				elapsed := now.Sub(lastTime).Seconds()
				totalElapsed := time.Since(startTime).Seconds()
				
				if elapsed < 0.5 {
					continue
				}
				
				currentCount := atomic.LoadUint64(&scanCount)
				opened := atomic.LoadUint64(&openCount)
				workers := atomic.LoadInt32(&totalScanners)
				
		
				recentRate := float64(currentCount - lastCount) / elapsed
				overallRate := float64(currentCount) / totalElapsed
				
			
				select {
				case rateChan <- recentRate:
				default:
					
				}
				
				fmt.Fprintf(os.Stderr, "\r[%s] Scanned: %d | Open: %d | Rate: %.2f ips/sec | Avg: %.2f | Target: %d ips/sec | Workers: %d", 
					time.Since(startTime).Round(time.Second), currentCount, opened, recentRate, overallRate, targetRate, workers)
				
				lastCount = currentCount
				lastTime = now
				
			case <-statusDone:
				return
			}
		}
	}()
	

	go dynamicWorkerAdjuster(&targetRate, workerControl, rateChan, workerDone)
	
	
	timeout := time.Duration(*timeoutFlag) * time.Second
	
	
	var wg sync.WaitGroup
	for i := 0; i < initialWorkers; i++ {
		wg.Add(1)
		go scanWorker(ipChan, *port, resultChan, &wg, timeout, workerDone)
	}
	
	
	if len(scanTargets) > 0 {
	
		go func() {
		
			batchSize := 2500
			
			for i := 0; i < len(scanTargets); i += batchSize {
				end := i + batchSize
				if end > len(scanTargets) {
					end = len(scanTargets)
				}
				
				
				for j := i; j < end; j++ {
					select {
					case ipChan <- scanTargets[j]:
					
					case <-generatorDone:
						return
					}
				}
			}
		}()
	} else {
	
		ipGen := NewIPGenerator()
		
		
		genCount := numCPU
		if genCount > 8 {
			genCount = 8
		}
		
		batchSize := targetRate / genCount
		if batchSize < 500 {
			batchSize = 500 
		}
		
		for i := 0; i < genCount; i++ {
			go generateIPs(ipGen, ipChan, batchSize, generatorDone)
		}
	}
	
	
	go func() {
		for delta := range workerControl {
			if delta > 0 {
			
				current := atomic.LoadInt32(&totalScanners)
				
				
				if current + int32(delta) > maxWorkers {
					delta = int(maxWorkers - current)
				}
				
				if delta > 0 {
					for i := 0; i < delta; i++ {
						wg.Add(1)
						atomic.AddInt32(&totalScanners, 1)
						go scanWorker(ipChan, *port, resultChan, &wg, timeout, workerDone)
					}
				}
			} else if delta < 0 {
				
				atomic.AddInt32(&totalScanners, int32(delta))
			}
		}
	}()
	

	scanDuration := time.Duration(*durationFlag) * time.Second
	scanEndTime := time.Now().Add(scanDuration)
	
	
	performanceTicker := time.NewTicker(5 * time.Second)
	defer performanceTicker.Stop()

	for time.Now().Before(scanEndTime) {
		select {
		case <-performanceTicker.C:
			
			elapsed := time.Since(startTime).Seconds()
			if elapsed > 10.0 {
				currentRate := float64(atomic.LoadUint64(&scanCount)) / elapsed
				currentWorkers := atomic.LoadInt32(&totalScanners)
				
				
				if currentRate < float64(minRate) && currentWorkers < maxWorkers-500 {
					boostWorkers := int(maxWorkers - currentWorkers) / 2
					if boostWorkers > 500 {
						boostWorkers = 500
					}
					
					if boostWorkers > 0 {
						select {
						case workerControl <- boostWorkers:
							if !quietMode {
								fmt.Fprintf(os.Stderr, "\nPerformance boost: Adding %d workers to reach target rate\n", boostWorkers)
							}
						default:
							
						}
					}
				}
			}
		default:
			time.Sleep(500 * time.Millisecond)
		}
	}
	
	
	if !quietMode {
		elapsed := time.Since(startTime).Seconds()
		scanned := atomic.LoadUint64(&scanCount)
		opened := atomic.LoadUint64(&openCount)
		
		fmt.Fprintf(os.Stderr, "\nScan completed in %s\n", time.Since(startTime).Round(time.Second))
		fmt.Fprintf(os.Stderr, "Scanned: %d IPs | Open: %d | Avg Rate: %.2f ips/s\n", 
			scanned, opened, float64(scanned)/elapsed)
	}
	
	
	close(generatorDone)
	close(statusDone)
	close(workerDone)
	
	
	time.Sleep(1 * time.Second)
	
	close(workerControl)
	close(resultChan)
}
