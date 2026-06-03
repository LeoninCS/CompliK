export function cn(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

export function formatDateTime(value: string | number | Date | null | undefined) {
  if (!value) return "-";

  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);

  const formatter = new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });

  return formatter.format(date).replace(/\//g, "-");
}

export function toDatetimeLocalValue(value: string | null | undefined) {
  if (!value) return "";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";

  const pad = (num: number) => String(num).padStart(2, "0");
  const year = date.getFullYear();
  const month = pad(date.getMonth() + 1);
  const day = pad(date.getDate());
  const hours = pad(date.getHours());
  const minutes = pad(date.getMinutes());

  return `${year}-${month}-${day}T${hours}:${minutes}`;
}

export function toTimestamp(value: string | number | Date | null | undefined) {
  if (!value) return 0;

  if (value instanceof Date) {
    return value.getTime();
  }

  if (typeof value === "number") {
    return value;
  }

  const normalized = value.includes(" ") ? value.replace(" ", "T") : value;
  const parsed = new Date(normalized).getTime();
  return Number.isNaN(parsed) ? 0 : parsed;
}

export function formatViolationTypeLabel(value: "complik" | "procscan") {
  return value === "complik" ? "内容违规" : "进程违规";
}

export function formatURLWithDeviceProfile(url: string | null | undefined, deviceProfile: string | null | undefined) {
  const trimmedURL = url?.trim() ?? "";
  if (!trimmedURL) {
    return "-";
  }

  const trimmedProfile = deviceProfile?.trim() ?? "";
  if (!trimmedProfile) {
    return trimmedURL;
  }

  return `${trimmedURL}（${trimmedProfile}）`;
}

export function summarizeMarkdown(value: string, maxLength = 80) {
  const collapsed = value
    .replace(/!\[([^\]]*)\]\([^)]+\)/g, "$1 ")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1 ")
    .replace(/[`>#*_~-]/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  if (!collapsed) {
    return "";
  }

  if (collapsed.length <= maxLength) {
    return collapsed;
  }

  return `${collapsed.slice(0, maxLength).trim()}...`;
}

export const FIXED_PAGE_SIZE = 10;

export function clampPage(page: number, totalPages: number) {
  if (totalPages <= 0) return 1;
  return Math.min(Math.max(page, 1), totalPages);
}

export function paginateItems<T>(items: T[], page: number, pageSize = FIXED_PAGE_SIZE) {
  const total = items.length;
  const totalPages = Math.ceil(total / pageSize);
  const safePage = clampPage(page, totalPages);
  const start = (safePage - 1) * pageSize;

  return {
    list: items.slice(start, start + pageSize),
    total,
    page: safePage,
    pageSize,
    totalPages,
  };
}
