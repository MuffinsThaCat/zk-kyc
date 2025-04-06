export function stringify(value: any): string {
  if (value == undefined || value == null) {
    throw new Error("Cannot stringify null or undefined");
  }
  return JSON.stringify(value, (_, v) => (typeof v === "bigint" ? `${v}n` : v));
}

export function parse(text: string): any {
  if (text == undefined || text == null) {
    throw new Error("Cannot stringify null or undefined");
  }

  return JSON.parse(text, (_, value) => {
    if (typeof value === "string") {
      const m = value.match(/(-?\d+)n/);
      if (m && m[0] === value) {
        value = BigInt(m[1]);
      }
    }
    return value;
  });
}
