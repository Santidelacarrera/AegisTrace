export const Badge = ({ sev }: { sev: string }) => <span className={`sev ${sev}`}>{sev}</span>;
export const ErrorBox = ({ msg }: { msg: string }) => (msg ? <p role="alert" className="error">{msg}</p> : null);
