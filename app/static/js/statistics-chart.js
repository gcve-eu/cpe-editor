import {VtChart} from "../vendor/vitrine/content/esm/vt-chart.js";
import {csvCell} from "./export-text.js";

class StatisticsChart extends VtChart {
  option(data) {
    const option = super.option(data);
    const width = this.parentElement?.clientWidth || this.clientWidth || 360;
    const labelWidth = Math.min(200, width * 0.45);
    // Reserve room for bars and avoid overlapping ticks on narrow screens.
    // The Table tab and tooltips retain the complete category labels.
    option.yAxis.axisLabel = {...option.yAxis.axisLabel,
      width: labelWidth, overflow: "truncate"};
    option.grid = {...option.grid, left: labelWidth + 20, bottom: 32, containLabel: false};
    option.xAxis.splitNumber = 2;
    option.xAxis.axisLabel.hideOverlap = true;
    return option;
  }
  draw() {
    super.draw();
    if (!this.instance) return;
    this.resize?.disconnect();
    this.resize = new ResizeObserver(() => {
      if (!this.instance) return;
      this.instance.resize();
      const {grid, xAxis, yAxis} = this.option(this.data);
      this.instance.setOption({grid, xAxis, yAxis});
    });
    this.resize.observe(this.plot);
  }
  csv() {
    const data = this.data;
    if (!data) return "";
    return [["Label", ...data.series.map(series => series.name)],
      ...data.labels.map((label, index) => [label, ...data.series.map(series => series.values[index])])]
      .map(row => row.map(csvCell).join(",")).join("\r\n");
  }
  copyButton(getText, ...args) { return super.copyButton(() => this.csv(), ...args); }
  downloadButton(getText, ...args) { return super.downloadButton(() => this.csv(), ...args); }
}
customElements.define("editor-chart", StatisticsChart);
