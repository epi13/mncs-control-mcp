import sys,time,json,resource,hashlib,subprocess,gc
from pathlib import Path
source=Path(sys.argv[1]);output=Path(sys.argv[2]);sys.path[:0]=[str(source/'src')]
from mncs_control_mcp.config import ControlConfig
from mncs_control_mcp.environment_sessions import EnvironmentService
from mncs_control_mcp.errors import ControlError
cfg=ControlConfig(workspace_root=Path('/home/epi13/Documents/Projects'))
counts={'store_opens':0,'store_closes':0,'snapshot_loads':0,'claims_reads':0,'native_batches':0,'git_processes':0}
setup=EnvironmentService(cfg);pkg=setup._pkg();store=setup._store(pkg)
snapshot=store.load_snapshot('ses_280bd7a394de6ac8');assert isinstance(snapshot,dict)
principal=snapshot['authenticated_principal_id'];assert isinstance(principal,str) and principal
checkout=snapshot['selected_checkouts']['mncs-control-mcp']
definition=snapshot['provenance']['definition_id'];workspace=snapshot['workspace']['root']
initial_generation=store.generation();inventory=len(store.list_sessions())
native_class=type(store.backend._store.session)
store.close()
if hasattr(setup,'close'):setup.close()
del setup,store,snapshot;gc.collect()
store_class=pkg.session_store.StoreSessionStore
original_open=pkg.session_store.open_store
original_close=store_class.close
original_load=store_class.load_snapshot
original_claims=store_class.read_claims
original_native=native_class.call_batch
original_run=subprocess.run
last_generation=initial_generation

def opened(*args,**kwargs):
 counts['store_opens']+=1
 return original_open(*args,**kwargs)
opened.__module__=original_open.__module__
def closed(self):
 global last_generation
 counts['store_closes']+=1;last_generation=self.generation()
 return original_close(self)
def loaded(self,*args,**kwargs):
 counts['snapshot_loads']+=1
 if counts['snapshot_loads']%100==0:print(json.dumps({'progress_snapshot_loads':counts['snapshot_loads']}),flush=True)
 return original_load(self,*args,**kwargs)
def claims(self,*args,**kwargs):counts['claims_reads']+=1;return original_claims(self,*args,**kwargs)
def native(self,*args,**kwargs):counts['native_batches']+=1;return original_native(self,*args,**kwargs)
def git(command,*args,**kwargs):
 if command and command[0]=='git':counts['git_processes']+=1
 return original_run(command,*args,**kwargs)
pkg.session_store.open_store=opened;store_class.close=closed;store_class.load_snapshot=loaded;store_class.read_claims=claims;native_class.call_batch=native;subprocess.run=git
service=EnvironmentService(cfg);service.authenticated_principal_id=principal
rows=[]
def cpu():
 own=resource.getrusage(resource.RUSAGE_SELF);child=resource.getrusage(resource.RUSAGE_CHILDREN)
 return own.ru_utime+child.ru_utime,own.ru_stime+child.ru_stime
try:
 for iteration in range(int(sys.argv[3]) if len(sys.argv)>3 else 2):
  before=dict(counts);user,system=cpu();start=time.perf_counter()
  result=service.campaign_continuation('mncs-control-mcp',working_checkout=checkout,definition_id=definition,workspace_root=workspace)
  elapsed=time.perf_counter()-start;enduser,endsystem=cpu()
  capsules=result.get('continuations',[])
  target_present=any(c.get('session_id')=='ses_280bd7a394de6ac8' for c in capsules)
  assert result.get('status')=='ready' and target_present, 'owned continuation was not returned'

  if getattr(service,'_store_pool',None):last_generation=service._store_pool[0].generation()
  row={'iteration':iteration,'seconds':elapsed,'user_cpu':enduser-user,'system_cpu':endsystem-system,**{k:counts[k]-before[k] for k in counts},'status':result.get('status'),'selected_session_id':result.get('selected_session_id'),'continuations':len(result.get('continuations',[])),'response_bytes':len(json.dumps(result).encode()),'response_sha256':hashlib.sha256(json.dumps(result,sort_keys=True).encode()).hexdigest(),'generation_after':last_generation,'target_present':target_present,'continuation_lifecycles':[c.get('lifecycle') for c in capsules],'next':result.get('next')}
  rows.append(row);print(json.dumps(row),flush=True)
except BaseException as error:
 rows.append({'incomplete':True,'error_type':type(error).__name__,'error_code':getattr(error,'code',None),'seconds':time.perf_counter()-start});raise
finally:
 if hasattr(service,'close'):service.close()
 output.write_text(json.dumps({'source':str(source),'sessions':inventory,'initial_generation':initial_generation,'rows':rows,'max_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'final_counts':counts},indent=2)+'\n')
