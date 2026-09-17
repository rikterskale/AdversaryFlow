import type { SVGProps } from "react";

export type IconName =
  | "arrow-left"
  | "arrow-right"
  | "check"
  | "close"
  | "help"
  | "moon"
  | "search"
  | "shield"
  | "sun";

const paths: Record<IconName, React.ReactNode> = {
  "arrow-left": <path d="m15 18-6-6 6-6" />,
  "arrow-right": <path d="m9 18 6-6-6-6" />,
  check: <path d="m5 12 4 4L19 6" />,
  close: <><path d="m6 6 12 12" /><path d="M18 6 6 18" /></>,
  help: <><circle cx="12" cy="12" r="9" /><path d="M9.6 9.2a2.5 2.5 0 1 1 3.3 2.4c-.8.4-1.4 1-1.4 2.1" /><path d="M12 17h.01" /></>,
  moon: <path d="M20 15.2A8.3 8.3 0 0 1 8.8 4 8.5 8.5 0 1 0 20 15.2Z" />,
  search: <><circle cx="11" cy="11" r="7" /><path d="m20 20-4-4" /></>,
  shield: <><path d="M12 3 19 6v6c0 4.4-3 7.4-7 8.6C8 19.4 5 16.4 5 12V6l7-3Z" /><path d="m9 12 2 2 4-4" /></>,
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></>,
};

interface IconProps extends SVGProps<SVGSVGElement> {
  name: IconName;
}

export function Icon({ name, ...props }: IconProps): JSX.Element {
  return (
    <svg aria-hidden="true" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" viewBox="0 0 24 24" {...props}>
      {paths[name]}
    </svg>
  );
}
