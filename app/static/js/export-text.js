export const spreadsheetText = value => {
  const text = typeof value === "object" && value !== null ? JSON.stringify(value) : String(value ?? "");
  return /^[\s\u0000-\u001f\u007f]*[=+\-@]/u.test(text) ? `'${text}` : text;
};
export const csvCell = value => `"${spreadsheetText(value).replaceAll('"', '""')}"`;
