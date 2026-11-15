/** Badge colours for advisory severities. */
export const SEVERITY_CLASS: Record<string, string> = {
  critical: 'border-[var(--danger)] bg-[var(--danger-soft)] text-[var(--danger)]',
  high: 'border-[var(--danger)] text-[var(--danger)]',
  medium: 'border-[var(--line)] text-[var(--text)]',
  low: 'border-[var(--line)] text-[var(--text-soft)]',
}
