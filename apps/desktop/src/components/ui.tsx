import { type ButtonHTMLAttributes, type ReactNode, useEffect, useId, useRef } from "react";

type Variant = "primary" | "secondary" | "ghost" | "danger";

const variants: Record<Variant, string> = {
  primary: "bg-accent text-accent-fg hover:brightness-110 border-transparent",
  secondary: "bg-surface text-fg border-line hover:bg-raised",
  ghost: "bg-transparent text-fg border-transparent hover:bg-raised",
  danger: "bg-danger text-white border-transparent hover:brightness-110",
};

export function Button({
  variant = "secondary",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }) {
  return (
    <button
      type="button"
      className={`inline-flex items-center justify-center gap-1.5 rounded-md border px-3 py-1.5 text-[13px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${variants[variant]} ${className}`}
      {...props}
    />
  );
}

export function Switch({
  checked,
  onChange,
  label,
  description,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  description?: ReactNode;
  disabled?: boolean;
}) {
  const id = useId();
  return (
    <div className="flex items-start justify-between gap-6 py-3">
      <div className="min-w-0">
        <label htmlFor={id} className="block font-medium">
          {label}
        </label>
        {description && (
          <div id={`${id}-d`} className="mt-0.5 max-w-[60ch] text-[13px] text-muted">
            {description}
          </div>
        )}
      </div>
      <button
        id={id}
        type="button"
        role="switch"
        aria-checked={checked}
        aria-describedby={description ? `${id}-d` : undefined}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`relative mt-0.5 h-5 w-9 shrink-0 rounded-full border transition-colors disabled:opacity-50 ${
          checked ? "border-accent bg-accent" : "border-line bg-raised"
        }`}
      >
        <span
          className={`absolute top-0.5 h-3.5 w-3.5 rounded-full transition-[left] ${
            checked ? "left-[18px] bg-accent-fg" : "left-0.5 bg-muted"
          }`}
        />
      </button>
    </div>
  );
}

export function TextField({
  label,
  value,
  onChange,
  error,
  hint,
  mono,
  placeholder,
  type = "text",
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  error?: string;
  hint?: string;
  mono?: boolean;
  placeholder?: string;
  type?: string;
}) {
  const id = useId();
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-[13px] font-medium">
        {label}
      </label>
      <input
        id={id}
        type={type}
        value={value}
        placeholder={placeholder}
        spellCheck={false}
        aria-invalid={!!error}
        aria-describedby={error || hint ? `${id}-m` : undefined}
        onChange={(e) => onChange(e.target.value)}
        className={`w-full rounded-md border bg-surface px-2.5 py-1.5 text-[13px] text-fg placeholder:text-muted/60 ${
          mono ? "font-mono" : ""
        } ${error ? "border-danger" : "border-line"}`}
      />
      {(error || hint) && (
        <p id={`${id}-m`} className={`mt-1 text-[12px] ${error ? "text-danger" : "text-muted"}`}>
          {error ?? hint}
        </p>
      )}
    </div>
  );
}

export type Tone = "ok" | "pending" | "bad" | "none";

export function Dot({ tone }: { tone: Tone }) {
  const c = {
    ok: "bg-accent",
    pending: "bg-pending",
    bad: "bg-danger",
    none: "bg-muted/50",
  }[tone];
  return <span aria-hidden className={`inline-block h-2 w-2 shrink-0 rounded-full ${c}`} />;
}

/** Key/value row. `state` makes unavailable/pending values explicit. */
export function Row({
  label,
  children,
  state = "confirmed",
}: {
  label: string;
  children?: ReactNode;
  state?: "confirmed" | "pending" | "unavailable";
}) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-line py-2 last:border-b-0">
      <dt className="shrink-0 text-muted">{label}</dt>
      <dd className="min-w-0 truncate text-right">
        {state === "unavailable" ? (
          <span className="text-muted">{children ?? "Unavailable"}</span>
        ) : state === "pending" ? (
          <span className="text-pending">{children ?? "Pending"}</span>
        ) : (
          children
        )}
      </dd>
    </div>
  );
}

export function Panel({
  title,
  actions,
  children,
  className = "",
}: {
  title?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-lg border border-line bg-surface ${className}`}>
      {title && (
        <header className="flex items-center justify-between border-b border-line px-4 py-2.5">
          <h2 className="text-[13px] font-semibold">{title}</h2>
          {actions}
        </header>
      )}
      <div className="px-4 py-1">{children}</div>
    </section>
  );
}

/** Native <dialog>: focus trap, Escape and inert background for free. */
export function Modal({
  open,
  onClose,
  title,
  children,
  wide,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal?.();
    if (!open && d.open) d.close?.();
  }, [open]);
  const titleId = useId();
  return (
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      onClose={onClose}
      className={`m-auto max-h-[85vh] w-[calc(100%-32px)] overflow-auto rounded-lg border border-line bg-surface p-0 text-fg shadow-2xl ${
        wide ? "max-w-3xl" : "max-w-md"
      }`}
    >
      {open && (
        <>
          <header className="sticky top-0 border-b border-line bg-surface px-5 py-3">
            <h2 id={titleId} className="font-semibold">
              {title}
            </h2>
          </header>
          <div className="px-5 py-4">{children}</div>
        </>
      )}
    </dialog>
  );
}

export function Confirm({
  open,
  title,
  body,
  confirmLabel,
  danger,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  body: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <Modal open={open} onClose={onCancel} title={title}>
      <div className="text-[13px] leading-relaxed">{body}</div>
      <div className="mt-5 flex justify-end gap-2">
        <Button onClick={onCancel} autoFocus>
          Cancel
        </Button>
        <Button variant={danger ? "danger" : "primary"} onClick={onConfirm}>
          {confirmLabel}
        </Button>
      </div>
    </Modal>
  );
}

/** Segmented choice built on native radios, so arrow keys and screen readers work as expected. */
export function Segmented<T extends string>({
  label,
  value,
  options,
  onChange,
  hideLabel,
}: {
  label: string;
  value: T;
  options: { value: T; label: string }[];
  onChange: (v: T) => void;
  hideLabel?: boolean;
}) {
  const name = useId();
  return (
    <fieldset>
      <legend className={hideLabel ? "sr-only" : "mb-1 text-[13px] font-medium"}>{label}</legend>
      <div className="flex flex-wrap gap-1.5">
        {options.map((o) => (
          <label key={o.value} className="cursor-pointer">
            <input
              type="radio"
              name={name}
              value={o.value}
              checked={value === o.value}
              onChange={() => onChange(o.value)}
              className="peer sr-only"
            />
            <span className="block rounded-md border border-line px-2.5 py-1 text-[12.5px] text-muted peer-checked:border-accent peer-checked:bg-accent-soft peer-checked:text-fg peer-focus-visible:outline-2 peer-focus-visible:outline-accent hover:text-fg">
              {o.label}
            </span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}
