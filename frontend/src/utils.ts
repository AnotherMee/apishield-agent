export function titleCase(value: string) {
  return value.replaceAll("-", " ").replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase())
}

export function severityClass(severity: string) {
  return `severity severity-${severity}`
}
