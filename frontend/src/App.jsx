import React, { useEffect, useMemo, useState } from "react";

const API = (import.meta.env.VITE_API_URL || "http://localhost:4000/api").replace(/\/$/, "");
const today = () => { const d = new Date(); d.setMinutes(d.getMinutes() - d.getTimezoneOffset()); return d.toISOString().slice(0,10); };
async function request(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) { const e = new Error(data.error || "Request failed."); e.status = response.status; e.data = data; throw e; }
  return data;
}
const blankReport = () => ({ date: today(), product: "", opening: 0, production: 0, returns: 0, dispatch: 0, notes: "" });
const csvCell = value => `"${String(value ?? "").replace(/"/g, '""')}"`;
function downloadCSV(filename, rows) {
  const csv = "\uFEFF" + rows.map(row => row.map(csvCell).join(",")).join("\r\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  const a = document.createElement("a"); a.href = url; a.download = filename; a.click(); URL.revokeObjectURL(url);
}

export default function App() {
  const [setupRequired, setSetupRequired] = useState(false);
  const [user, setUser] = useState(null);
  const [mode, setMode] = useState("login");
  const [products, setProducts] = useState([]);
  const [reports, setReports] = useState([]);
  const [users, setUsers] = useState([]);
  const [auditRows, setAuditRows] = useState([]);
  const [report, setReport] = useState(blankReport());
  const [editingId, setEditingId] = useState(null);
  const [filterDate, setFilterDate] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [busy, setBusy] = useState(false);

  const [auth, setAuth] = useState({ username: "", password: "", password2: "", recoveryCode: "" });
  const [newUser, setNewUser] = useState({ username: "", password: "" });

  const visibleReports = useMemo(() => reports.filter(r => !filterDate || r.date === filterDate), [reports, filterDate]);
  const closing = Number(report.opening || 0) + Number(report.production || 0) + Number(report.returns || 0) - Number(report.dispatch || 0);
  const isAdmin = user?.role === "admin";

  const flash = (text, isError = false) => { setMessage(isError ? "" : text); setError(isError ? text : ""); };
  async function loadDashboard() {
    const [p, r] = await Promise.all([request("/products"), request("/reports")]);
    setProducts(p.products); setReports(r.reports);
    if (user?.role === "admin") {
      const [u, a] = await Promise.all([request("/users"), request("/audit")]);
      setUsers(u.users); setAuditRows(a.audit);
    }
  }
  useEffect(() => {
    (async () => {
      try {
        const status = await request("/auth/status");
        setSetupRequired(status.setupRequired);
        if (status.setupRequired) { setMode("setup"); return; }
        try {
          const me = await request("/auth/me"); setUser(me.user);
        } catch { setMode("login"); }
      } catch (e) { flash(`${e.message} Ensure the backend is running and MongoDB is configured.`, true); }
    })();
  }, []);
  useEffect(() => { if (user) loadDashboard().catch(e => flash(e.message, true)); }, [user?.id]);

  async function submitAuth(e) {
    e.preventDefault(); setBusy(true); flash("");
    try {
      if (mode === "setup") {
        if (auth.password !== auth.password2) throw new Error("Passwords do not match.");
        const data = await request("/auth/setup", { method: "POST", body: JSON.stringify(auth) });
        setRecoveryCode(data.recoveryCode); setUser(data.user); setSetupRequired(false);
        flash("Administrator created. Save the recovery code displayed below.");
      } else if (mode === "login") {
        const data = await request("/auth/login", { method: "POST", body: JSON.stringify(auth) });
        setUser(data.user); setAuth({ username: "", password: "", password2: "", recoveryCode: "" }); flash("Signed in successfully.");
      } else {
        if (auth.password !== auth.password2) throw new Error("Passwords do not match.");
        const data = await request("/auth/reset", { method: "POST", body: JSON.stringify(auth) });
        setRecoveryCode(data.recoveryCode); setMode("login"); flash("Password reset. Save your new recovery code.");
      }
    } catch (e) { flash(e.message, true); }
    finally { setBusy(false); }
  }
  async function logout() {
    try { await request("/auth/logout", { method: "POST" }); } catch {}
    setUser(null); setReports([]); setUsers([]); setAuditRows([]); setMode("login"); setRecoveryCode(""); flash("You have been logged out.");
  }
  const setField = (key, value) => setReport(old => ({ ...old, [key]: value }));
  function clearReport() { setReport(blankReport()); setEditingId(null); }
  async function saveReport(e) {
    e.preventDefault(); setBusy(true); flash("");
    try {
      const values = { ...report, opening: Number(report.opening), production: Number(report.production), returns: Number(report.returns), dispatch: Number(report.dispatch) };
      if (values.dispatch > values.opening + values.production + values.returns) throw new Error("Dispatch cannot exceed opening stock + production + returns.");
      if (editingId) await request(`/reports/${editingId}`, { method: "PUT", body: JSON.stringify(values) });
      else {
        try { await request("/reports", { method: "POST", body: JSON.stringify(values) }); }
        catch (e) {
          if (e.status === 409 && e.data?.duplicate && window.confirm("A report for this product and date already exists. Create another?")) {
            await request("/reports", { method: "POST", body: JSON.stringify({ ...values, allowDuplicate: true }) });
          } else throw e;
        }
      }
      clearReport(); await loadDashboard(); flash("Report saved successfully.");
    } catch (e) { flash(e.message, true); }
    finally { setBusy(false); }
  }
  function editReport(r) {
    if (!isAdmin && r.status === "Approved") return flash("Approved reports are locked. Ask an administrator.", true);
    setEditingId(r.id); setReport({ date:r.date, product:r.product, opening:r.opening, production:r.production, returns:r.returns, dispatch:r.dispatch, notes:r.notes || "" });
    document.getElementById("report-form")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }
  async function approve(id) {
    try { await request(`/reports/${id}/approve`, { method: "POST" }); await loadDashboard(); flash("Report approved."); }
    catch (e) { flash(e.message, true); }
  }
  async function deleteReport(id) {
    if (!window.confirm("Permanently delete this report? Export a backup first if needed.")) return;
    try { await request(`/reports/${id}`, { method: "DELETE" }); await loadDashboard(); flash("Report deleted."); }
    catch (e) { flash(e.message, true); }
  }
  async function createUser(e) {
    e.preventDefault();
    try {
      const data = await request("/users", { method: "POST", body: JSON.stringify(newUser) });
      setRecoveryCode(data.recoveryCode); setNewUser({ username:"", password:"" }); await loadDashboard();
      flash(`Created ${data.user.username}. Copy and securely provide the one-time recovery code below.`);
    } catch (e) { flash(e.message, true); }
  }
  async function toggleUser(id) {
    try { await request(`/users/${id}/toggle`, { method: "PATCH" }); await loadDashboard(); flash("User account updated."); }
    catch (e) { flash(e.message, true); }
  }
  async function removeUser(id, name) {
    if (!window.confirm(`Delete ${name}? Their reports will remain in the database.`)) return;
    try { await request(`/users/${id}`, { method: "DELETE" }); await loadDashboard(); flash("User deleted."); }
    catch (e) { flash(e.message, true); }
  }
  function exportReports() {
    const rows = [["Date","Product","Owner","Opening","Production","Returns","Dispatch","Closing","Status","Notes"],
      ...visibleReports.map(r => [r.date,r.product,r.ownerName,r.opening,r.production,r.returns,r.dispatch,r.closing,r.status,r.notes])];
    downloadCSV(`DPR_reports_${today()}.csv`, rows);
  }
  function exportAudit() {
    downloadCSV(`DPR_audit_${today()}.csv`, [["Time","Actor","Action","Details"], ...auditRows.map(a => [a.at,a.actor,a.action,a.details])]);
  }
  function printReports(rows, title = "Daily Production Reports") {
    const win = window.open("", "_blank");
    if (!win) return flash("Allow pop-ups to print reports.", true);
    const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
    win.document.write(`<!doctype html><html><head><title>${esc(title)}</title><meta charset="utf-8"><style>body{font:12px Arial;padding:20px}h1{font-size:20px}table{width:100%;border-collapse:collapse}th,td{border:1px solid #aaa;padding:7px;text-align:left}th{background:#eee}</style></head><body><h1>${esc(title)}</h1><p>Generated: ${esc(new Date().toLocaleString())}</p><table><thead><tr>${["Date","Product","Owner","Opening","Production","Returns","Dispatch","Closing","Status","Notes"].map(x=>`<th>${x}</th>`).join("")}</tr></thead><tbody>${rows.map(r=>`<tr>${[r.date,r.product,r.ownerName,r.opening,r.production,r.returns,r.dispatch,r.closing,r.status,r.notes].map(v=>`<td>${esc(v)}</td>`).join("")}</tr>`).join("")}</tbody></table><script>window.onload=()=>window.print()<\/script></body></html>`);
    win.document.close();
  }

  if (!user) return <><header><div><h1>Daily Production Report</h1><small>Secure DPR workspace · Role-based access</small></div></header><main className="auth">
    <section className="panel">
      <h2>{mode === "setup" ? "Initial administrator setup" : mode === "reset" ? "Recover account" : "Sign in"}</h2>
      {mode === "setup" && <div className="notice warning">First launch: create the first administrator. There is no default administrator password. Save the recovery code shown after setup.</div>}
      {mode === "reset" && <div className="notice warning">Use the recovery code saved when the account was created. Recovery is not email-based.</div>}
      <form onSubmit={submitAuth}>
        <label>Username</label><input autoComplete="username" required maxLength="40" value={auth.username} onChange={e=>setAuth({...auth,username:e.target.value})}/>
        {mode === "reset" && <><label>Recovery code</label><input required value={auth.recoveryCode} onChange={e=>setAuth({...auth,recoveryCode:e.target.value})}/></>}
        <label>{mode === "reset" ? "New password (12+ characters)" : "Password"}</label><input type="password" autoComplete={mode==="login"?"current-password":"new-password"} minLength={mode==="login"?undefined:12} required value={auth.password} onChange={e=>setAuth({...auth,password:e.target.value})}/>
        {mode !== "login" && <><label>Confirm password</label><input type="password" minLength="12" required value={auth.password2} onChange={e=>setAuth({...auth,password2:e.target.value})}/></>}
        <button disabled={busy}>{busy ? "Please wait…" : mode==="setup" ? "Create administrator" : mode==="reset" ? "Reset password" : "Sign in"}</button>
        {mode==="login" && <button type="button" className="light" onClick={()=>setMode("reset")}>Reset password</button>}
        {mode==="reset" && <button type="button" className="light" onClick={()=>setMode("login")}>Back to login</button>}
      </form>
      {recoveryCode && <div className="notice success"><strong>Save this one-time recovery code now:</strong><p className="code">{recoveryCode}</p><button className="secondary" onClick={()=>navigator.clipboard?.writeText(recoveryCode)}>Copy recovery code</button></div>}
      {message && <div className="notice success">{message}</div>}{error && <div className="notice error">{error}</div>}
      {setupRequired && mode !== "setup" && <button onClick={()=>setMode("setup")}>Initial setup</button>}
    </section>
    <footer>Secure DPR · React, Express and MongoDB</footer>
  </main></>;

  return <>
    <header><div><h1>Daily Production Report</h1><small>Secure DPR workspace · Database-backed application</small></div><div className="account"><span>{user.username} · {user.role.toUpperCase()}</span><button className="light" onClick={logout}>Log out</button></div></header>
    <main>
      {(message || error || recoveryCode) && <div className={`notice ${error?"error":recoveryCode?"success":""}`}>{error || message}{recoveryCode && <div><strong>One-time recovery code — save it securely:</strong><p className="code">{recoveryCode}</p><button className="secondary" onClick={()=>navigator.clipboard?.writeText(recoveryCode)}>Copy recovery code</button><button className="light" onClick={()=>setRecoveryCode("")}>Dismiss</button></div>}</div>}
      <section className="panel"><div className="row"><div><h2>Welcome, {user.username}</h2><p className="muted">{isAdmin ? "Admin: view all reports, correct reports, approve reports, and manage accounts." : "User: create reports and manage your own reports."}</p></div><span className="tag">{user.role.toUpperCase()}</span></div>
        <div className="notice warning">Access is enforced by the backend. Use a strong password and keep your recovery code private.</div></section>
      <div className="cards"><div className="stat"><span>Total visible reports</span><strong>{reports.length}</strong></div><div className="stat"><span>Pending review</span><strong>{reports.filter(r=>r.status==="Pending").length}</strong></div><div className="stat"><span>Approved reports</span><strong>{reports.filter(r=>r.status==="Approved").length}</strong></div></div>

      <section className="panel" id="report-form"><h2>{editingId ? (isAdmin ? "Admin: correct report" : "Edit your report") : "Create daily report"}</h2>
        <form onSubmit={saveReport}><div className="grid">
          <div><label>Report date</label><input type="date" required value={report.date} onChange={e=>setField("date",e.target.value)}/></div>
          <div><label>Product / item</label><select required value={report.product} onChange={e=>setField("product",e.target.value)}><option value="">Select a product…</option>{products.map(p=><option key={p} value={p}>{p}</option>)}</select></div>
          {["opening","production","returns","dispatch"].map((field,i)=><div key={field}><label>{["Opening stock","Production quantity","Return quantity","Dispatch quantity"][i]}</label><input type="number" min="0" max="1000000000" step="1" required value={report[field]} onChange={e=>setField(field,e.target.value)}/></div>)}
          <div><label>Notes</label><input maxLength="500" placeholder="Optional" value={report.notes} onChange={e=>setField("notes",e.target.value)}/></div>
        </div><div className="notice"><strong>Calculated closing stock: {closing}</strong><p className="muted">Opening + production + returns − dispatch. Dispatch cannot exceed available stock.</p></div>
          <button disabled={busy}>{busy?"Saving…":editingId?"Save changes":"Save report"}</button><button type="button" className="light" onClick={clearReport}>Clear form</button>{editingId && <button type="button" className="secondary" onClick={clearReport}>Cancel editing</button>}
        </form>
      </section>

      <section className="panel"><div className="row"><h2>Reports</h2><div className="filter"><label>Filter date</label><input type="date" value={filterDate} onChange={e=>setFilterDate(e.target.value)}/></div></div><p className="muted">{isAdmin?"You can see all users' reports. Review, correct or approve them.":"You can see and edit only your own reports."}</p>
        <div className="tablewrap"><table><thead><tr>{["Date","Product","Owner","Opening","Production","Returns","Dispatch","Closing","Status","Actions"].map(x=><th key={x}>{x}</th>)}</tr></thead><tbody>
          {visibleReports.map(r=><tr key={r.id}><td>{r.date}</td><td>{r.product}</td><td>{r.ownerName}</td><td>{r.opening}</td><td>{r.production}</td><td>{r.returns}</td><td>{r.dispatch}</td><td>{r.closing}</td><td><span className={`tag ${r.status==="Approved"?"approved":"pending"}`}>{r.status}</span></td><td className="actions"><button className="secondary" onClick={()=>editReport(r)}>Edit</button>{isAdmin && r.status!=="Approved" && <button className="green" onClick={()=>approve(r.id)}>Approve</button>}<button className="light" onClick={()=>printReports([r],"Daily Production Report")}>Print</button>{isAdmin && <button className="danger" onClick={()=>deleteReport(r.id)}>Delete</button>}</td></tr>)}
          {!visibleReports.length && <tr><td colSpan="10">No reports found for this date.</td></tr>}
        </tbody></table></div>
      </section>

      {isAdmin && <section className="panel"><h2>Admin: user management</h2><p className="muted">Create or disable user accounts. Usernames cannot be reused while an account exists.</p>
        <form onSubmit={createUser}><div className="grid"><div><label>New username</label><input required minLength="3" maxLength="40" value={newUser.username} onChange={e=>setNewUser({...newUser,username:e.target.value})}/></div><div><label>Initial password (12+ characters)</label><input type="password" required minLength="12" maxLength="128" value={newUser.password} onChange={e=>setNewUser({...newUser,password:e.target.value})}/></div></div><button>Create user</button></form>
        <div className="tablewrap"><table><thead><tr><th>Username</th><th>Role</th><th>Account</th><th>Action</th></tr></thead><tbody>{users.map(u=><tr key={u.id}><td>{u.username}</td><td>{u.role}</td><td>{u.active?"Active":"Disabled"}</td><td>{u.role==="admin"?<span className="muted">Protected admin</span>:<><button className={u.active?"danger":"green"} onClick={()=>toggleUser(u.id)}>{u.active?"Disable":"Enable"}</button><button className="danger" onClick={()=>removeUser(u.id,u.username)}>Delete</button></>}</td></tr>)}</tbody></table></div>
      </section>}

      {isAdmin && <section className="panel"><div className="row"><div><h2>Admin: audit history</h2><p className="muted">Login attempts, report changes, approvals, and account management.</p></div><div><button className="secondary" onClick={exportAudit}>Export audit CSV</button><button className="light" onClick={()=>loadDashboard().catch(e=>flash(e.message,true))}>Refresh</button></div></div>
        <div className="tablewrap"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Details</th></tr></thead><tbody>{auditRows.slice(0,300).map(a=><tr key={a._id}><td>{new Date(a.at).toLocaleString()}</td><td>{a.actor}</td><td>{a.action}</td><td>{a.details}</td></tr>)}</tbody></table></div>
      </section>}

      <section className="panel"><h2>Export</h2><p className="muted">Print the currently visible reports and select “Save as PDF” in your browser's print dialog.</p><button onClick={()=>printReports(visibleReports)}>Print / Save visible reports as PDF</button><button className="secondary" onClick={exportReports}>Export visible reports as CSV</button></section>
    </main>
    <footer>Secure DPR · MERN stack · Server-side authentication and MongoDB persistence</footer>
  </>;
}
