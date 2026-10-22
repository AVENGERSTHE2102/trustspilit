export default function FlowDiagram({active,live}:{active:boolean;live:boolean;blocked?:boolean}){
 return <div className={`paired-flow ${active?"is-active":""}`} aria-label="Baseline and guarded benchmark paths">
  <svg className="paired-wires" viewBox="0 0 1000 290" preserveAspectRatio="none" aria-hidden="true">
   <path className="flow-line raw-line" d="M146 144 H205 V72 H260 M205 144 V218 H260 M420 72 H500"/>
   <path className="flow-line clean-line" d="M420 218 H500"/>
   <path className="flow-line policy-line" d="M660 72 H790 M660 218 H790"/>
   {active&&<><circle className="flow-bead raw-bead" r="4"><animateMotion dur="2.6s" repeatCount="indefinite" path="M146 144 H205 V72 H260 M205 144 V218 H260"/></circle><circle className="flow-bead clean-bead" r="4"><animateMotion dur="2.8s" repeatCount="indefinite" path="M420 218 H500"/></circle><circle className="flow-bead model-bead" r="4"><animateMotion dur="3s" repeatCount="indefinite" path="M420 72 H500"/></circle><circle className="flow-bead policy-bead" r="4"><animateMotion dur="3.2s" repeatCount="indefinite" path="M660 218 H790"/></circle></>}
  </svg>
  <div className="flow-source"><span>01 · SOURCE</span><b>Untrusted text</b><small>same input in both arms</small></div>
  <div className="flow-lane-label baseline-label">BASELINE</div><div className="flow-lane-label guarded-label">GUARDED</div>
  <div className="flow-node-bench baseline-context"><span>RAW CONTEXT</span><b>Unmodified</b><small>injection included</small></div>
  <div className="flow-node-bench guard-context"><span>LOCAL SCREEN</span><b>Gemma 3 · 1B</b><small>{live?"Ollama · local call":"fixture signal"}</small></div>
  <div className="flow-node-bench baseline-model"><span>MODEL CALL 01</span><b>Claude</b><small>{live?"Anthropic API":"fixture"}</small></div>
  <div className="flow-node-bench guarded-model"><span>MODEL CALL 02</span><b>Claude</b><small>{live?"Anthropic API":"fixture"}</small></div>
  <div className="flow-node-bench baseline-policy"><span>DECISION 01</span><b>Policy gate</b><small>proposal only</small></div>
  <div className="flow-node-bench guarded-policy"><span>DECISION 02</span><b>Policy gate</b><small>no tools execute</small></div>
  <div className="flow-edge-label raw-edge">RAW</div><div className="flow-edge-label safe-edge">SCREENED</div>
  <div className="flow-callout">Both arms use the same server-owned plan and deterministic policy.</div>
 </div>
}
