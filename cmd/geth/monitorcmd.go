// Copyright 2015 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"log"
	"math"
	"runtime"
	"strings"
	"time"

	"sort"

	"path/filepath"
	"regexp"

	"github.com/gizak/termui"
	"github.com/kar98kar/go-ulogos/common"
	"github.com/kar98kar/go-ulogos/logger/glog"
	"github.com/kar98kar/go-ulogos/node"
	"github.com/kar98kar/go-ulogos/rpc"
	"gopkg.in/urfave/cli.v1"
)

var (
	monitorCommandAttachFlag = cli.StringFlag{
		Name:  "attach",
		Value: "ipc:" + node.DefaultIPCEndpoint(filepath.Join(common.DefaultDataDir(), "mainnet")),
		Usage: "API endpoint to attach to",
	}
	monitorCommandRowsFlag = cli.IntFlag{
		Name:  "rows",
		Value: 5,
		Usage: "Maximum rows in the chart grid",
	}
	monitorCommandRefreshFlag = cli.IntFlag{
		Name:  "refresh",
		Value: 3,
		Usage: "Refresh interval in seconds",
	}
	monitorCommand = cli.Command{
		Action: monitor,
		Name:   "monitor",
		Usage:  `Geth Monitor: node metrics monitoring and visualization`,
		Description: `
	The Geth monitor is a tool to collect and visualize various internal metrics
	gathered by the node, supporting different chart types as well as the capacity
	to display multiple metrics simultaneously.
		`,
		Flags: []cli.Flag{
			monitorCommandAttachFlag,
			monitorCommandRowsFlag,
			monitorCommandRefreshFlag,
		},
	}
)

// monitor starts a terminal UI based monitoring tool for the requested metrics.
func monitor(ctx *cli.Context) error {
	// Attach to an Ethereum node over IPC or RPC
	endpoint := ctx.String(monitorCommandAttachFlag.Name)
	// Set defaults (no arg value) to chain contextual path (via --chain or --testnet, since default val is mainnet)
	if ctx.GlobalString(monitorCommandAttachFlag.Name) == "" {
		endpoint = "ipc:" + node.DefaultIPCEndpoint(MustMakeChainDataDir(ctx))
	}
	client, err := rpc.NewClient(endpoint)
	if err != nil {
		log.Fatal("attach to remote geth: ", err)
	}
	defer client.Close()

	// Retrieve all the available metrics and resolve the user pattens
	metrics, err := retrieveMetrics(client)
	if err != nil {
		log.Fatalf("Failed to retrieve system metrics: %s", err)
	}
	monitored := resolveMetrics(metrics, ctx.Args())
	if len(monitored) == 0 {
		list := expandMetrics(metrics, "")
		sort.Strings(list)

		if len(list) > 0 {
			if len(ctx.Args()) == 0 {
				log.Fatalf("No metrics specified. Available: \n%s", listWithNewlines(list))
			}
			log.Fatalf("No metrics found matching that pattern. Available metrics: \n%s", listWithNewlines(list))
		} else {
			log.Fatal("No metrics collected by geth (--metrics).")
		}
	}
	sort.Strings(monitored)
	if cols := len(monitored) / ctx.Int(monitorCommandRowsFlag.Name); cols > 6 {
		log.Fatalf("Requested metrics spans more that 6 columns: %q", monitored)
	}
	// Create and configure the chart UI defaults
	if err := termui.Init(); err != nil {
		log.Fatalf("Unable to initialize terminal UI: %s", err)
	}
	defer termui.Close()

	rows := len(monitored)
	if max := ctx.Int(monitorCommandRowsFlag.Name); rows > max {
		rows = max
	}
	cols := (len(monitored) + rows - 1) / rows
	for i := 0; i < rows; i++ {
		termui.Body.AddRows(termui.NewRow())
	}
	// Create each individual data chart
	footer := termui.NewPar("")
	footer.Block.Border = true
	footer.Height = 3

	charts := make([]*termui.LineChart, len(monitored))
	units := make([]int, len(monitored))
	data := make([][]float64, len(monitored))
	for i := 0; i < len(monitored); i++ {
		charts[i] = createChart((termui.TermHeight() - footer.Height) / rows)
		row := termui.Body.Rows[i%rows]
		row.Cols = append(row.Cols, termui.NewCol(12/cols, 0, charts[i]))
	}
	termui.Body.AddRows(termui.NewRow(termui.NewCol(12, 0, footer)))

	refreshCharts(client, monitored, data, units, charts, ctx, footer)
	termui.Body.Align()
	termui.Render(termui.Body)

	// Watch for various system events, and periodically refresh the charts
	termui.Handle("/sys/kbd/C-c", func(termui.Event) {
		termui.StopLoop()
	})
	termui.Handle("/sys/wnd/resize", func(termui.Event) {
		termui.Body.Width = termui.TermWidth()
		for _, chart := range charts {
			chart.Height = (termui.TermHeight() - footer.Height) / rows
		}
		termui.Body.Align()
		termui.Render(termui.Body)
	})
	go func() {
		tick := time.NewTicker(time.Duration(ctx.Int(monitorCommandRefreshFlag.Name)) * time.Second)
		for range tick.C {
			if refreshCharts(client, monitored, data, units, charts, ctx, footer) {
				termui.Body.Align()
			}
			termui.Render(termui.Body)
		}
	}()
	termui.Loop()
	return nil
}

// listWithNewlines is a convenience function for showing available
// metrics in case there are none specified or no matches
func listWithNewlines(availableMetrics []string) string {
	return strings.Join(availableMetrics, "\n")
}

// retrieveMetrics contacts the attached geth node and retrieves the entire set
// of collected system metrics.
func retrieveMetrics(client rpc.Client) (map[string]float64, error) {
	req := map[string]interface{}{
		"id":      new(int64),
		"method":  "debug_metrics",
		"jsonrpc": "2.0",
		"params":  []interface{}{true},
	}

	if err := client.Send(req); err != nil {
		return nil, err
	}

	var res rpc.JSONResponse
	if err := client.Recv(&res); err != nil {
		return nil, err
	}

	if res.Result != nil {
		r, ok := res.Result.(map[string]interface{})
		if !ok {
			glog.Fatalln("Could not convert resulting JSON response to type map[string]interface{}")
		}

		if ok {
			return flattenToFloat(r), nil
		}
	}

	return nil, fmt.Errorf("unable to retrieve metrics")
}

// resolveMetrics takes a list of input metric patterns, and resolves each to one
// or more canonical metric names.
// 'patterns' are user-inputed arguments
// eg.
// $ geth monitor [--attach=api-endpoint] metric1 metric2 ... metricN
//
// Where a metric may be: a REGEX to match available metrics paths/strings/names
func resolveMetrics(metrics map[string]float64, patterns []string) []string {
	res := []string{}
	for _, pattern := range patterns {
		res = append(res, resolveMetric(metrics, pattern, "")...)
	}
	return res
}

// resolveMetrics takes a single of input metric pattern, and resolves it to one
// or more canonical metric names.
func resolveMetric(metrics map[string]float64, pattern string, path string) []string {
	var out []string
	re := regexp.MustCompile(pattern)
	for met := range metrics {
		if re.MatchString(met) {
			out = append(out, met)
		}
	}
	return out
}

// expandMetrics expands the entire tree of metrics into a flat list of paths.
func expandMetrics(metrics map[string]float64, path string) []string {
	var list []string
	for k := range metrics {
		list = append(list, k)
	}
	return list
}

// flattenToFloat takes:
/*
p2p/bytes/in: map[string]interface{}
where interface{} val is:
map{
  15m.rate: 0
  5m.rate: 4
  1m.rate: 1.3
  mean.rate: 0.7222
  count: 14
}

and returns:
map{
p2p/bytes/in/15m.rate: 0
p2p/bytes/in/5m.rate: 4
p2p/bytes/in/1m.rate: 1.3
p2p/bytes/in/mean.rate: 0.7222
p2p/bytes/in/count: 14
}

*/
func flattenToFloat(rawMets map[string]interface{}) map[string]float64 {
	var mets = make(map[string]float64)
	for k, v := range rawMets {
		if vi, ok := v.(map[string]interface{}); ok {
			for vk, vv := range vi {
				if f, fok := vv.(float64); fok {
					mets[k+"/"+vk] = f
				}
			}
		}
	}
	return mets
}

// refreshCharts retrieves a next batch of metrics, and inserts all the new
// values into the active datasets and charts
func refreshCharts(client rpc.Client, metrics []string, data [][]float64, units []int, charts []*termui.LineChart, ctx *cli.Context, footer *termui.Par) (realign bool) {
	values, err := retrieveMetrics(client)
	for i, metric := range metrics {
		if len(data) < 512 {
			data[i] = append([]float64{values[metric]}, data[i]...)
		} else {
			data[i] = append([]float64{values[metric]}, data[i][:len(data[i])-1]...)
		}
		if updateChart(metric, data[i], &units[i], charts[i], err) {
			realign = true
		}
	}
	updateFooter(ctx, err, footer)
	return
}

// updateChart inserts a dataset into a line chart, scaling appropriately as to
// not display weird labels, also updating the chart label accordingly.
func updateChart(metric string, data []float64, base *int, chart *termui.LineChart, err error) (realign bool) {
	dataUnits := []string{"", "K", "M", "G", "T", "E"}
	timeUnits := []string{"ns", "µs", "ms", "s", "ks", "ms"}
	colors := []termui.Attribute{termui.ColorBlue, termui.ColorCyan, termui.ColorGreen, termui.ColorYellow, termui.ColorRed, termui.ColorRed}

	// Extract only part of the data that's actually visible
	if chart.Width*2 < len(data) {
		data = data[:chart.Width*2]
	}
	// Find the maximum value and scale under 1K
	high := 0.0
	if len(data) > 0 {
		high = data[0]
		for _, value := range data[1:] {
			high = math.Max(high, value)
		}
	}
	unit, scale := 0, 1.0
	for high >= 1000 && unit+1 < len(dataUnits) {
		high, unit, scale = high/1000, unit+1, scale*1000
	}
	// If the unit changes, re-create the chart (hack to set max height...)
	if unit != *base {
		realign, *base, *chart = true, unit, *createChart(chart.Height)
	}
	// Update the chart's data points with the scaled values
	if cap(chart.Data) < len(data) {
		chart.Data = make([]float64, len(data))
	}
	chart.Data = chart.Data[:len(data)]
	for i, value := range data {
		chart.Data[i] = value / scale
	}
	// Update the chart's label with the scale units
	units := dataUnits
	if strings.Contains(metric, "/Percentiles/") || strings.Contains(metric, "/pauses/") || strings.Contains(metric, "/time/") {
		units = timeUnits
	}
	chart.BorderLabel = metric
	if len(units[unit]) > 0 {
		chart.BorderLabel += " [" + units[unit] + "]"
	}
	chart.LineColor = colors[unit] | termui.AttrBold
	if err != nil {
		chart.LineColor = termui.ColorRed | termui.AttrBold
	}
	return
}

// createChart creates an empty line chart with the default configs.
func createChart(height int) *termui.LineChart {
	chart := termui.NewLineChart()
	if runtime.GOOS == "windows" {
		chart.Mode = "dot"
	}
	chart.DataLabels = []string{""}
	chart.Height = height
	chart.AxesColor = termui.ColorWhite
	chart.PaddingBottom = -2

	chart.BorderLabelFg = chart.BorderFg | termui.AttrBold
	chart.BorderFg = chart.BorderBg

	return chart
}

// updateFooter updates the footer contents based on any encountered errors.
func updateFooter(ctx *cli.Context, err error, footer *termui.Par) {
	// Generate the basic footer
	refresh := time.Duration(ctx.Int(monitorCommandRefreshFlag.Name)) * time.Second
	footer.Text = fmt.Sprintf("Press Ctrl+C to quit. Refresh interval: %v.", refresh)
	footer.TextFgColor = termui.ThemeAttr("par.fg") | termui.AttrBold

	// Append any encountered errors
	if err != nil {
		footer.Text = fmt.Sprintf("Error: %v.", err)
		footer.TextFgColor = termui.ColorRed | termui.AttrBold
	}
}

// sliceContainsStrings is a convenience helper function for resolving metrics paths
func sliceContainsString(slice []string, s string) bool {
	for _, sl := range slice {
		if sl == s {
			return true
		}
	}
	return false
}
