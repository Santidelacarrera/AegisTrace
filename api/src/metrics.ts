/** Minimal Prometheus-style cumulative histogram. */
export class Histogram {
  private counts: number[];
  private sum = 0;
  private n = 0;
  constructor(private bounds: number[]) { this.counts = bounds.map(() => 0); }
  observe(v: number) { this.n++; this.sum += v; this.bounds.forEach((b, i) => { if (v <= b) this.counts[i]!++; }); }
  render(name: string): string[] {
    return [...this.bounds.map((b, i) => `${name}_bucket{le="${b}"} ${this.counts[i]}`), `${name}_bucket{le="+Inf"} ${this.n}`, `${name}_sum ${this.sum.toFixed(3)}`, `${name}_count ${this.n}`];
  }
}
