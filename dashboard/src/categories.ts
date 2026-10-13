/*
 * Plain-language names for the detection engine's threat categories. Keys
 * must match the CATEGORY_* constants in backend/app/detection/heuristics.py.
 */
const CATEGORY_LABELS: Record<string, string> = {
  impersonation: "Pretending to be a company",
  dangerous_link: "Dangerous or disguised links",
  pressure_language: "Pressure to act fast",
  scam_request: "Scam requests (gift cards, fake charges)",
  info_request: "Asking for personal details",
  suspicious_sender: "Suspicious sender address",
};

export function categoryLabel(category: string): string {
  return CATEGORY_LABELS[category] ?? category.replace(/_/g, " ");
}
