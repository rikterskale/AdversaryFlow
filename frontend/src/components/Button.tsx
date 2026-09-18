import type { ButtonHTMLAttributes } from "react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "ghost";
}

export function Button({ className = "", variant = "secondary", ...props }: ButtonProps): React.JSX.Element {
  return <button className={`button button--${variant} ${className}`.trim()} type="button" {...props} />;
}
