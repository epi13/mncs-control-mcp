import json,sys,time,resource
from pathlib import Path
source=Path(sys.argv[1]);output=Path(sys.argv[2]);sys.path.insert(0,str(source/'src'))
from mncs_control_mcp.config import ControlConfig
import mncs_control_mcp.environment_sessions as module
workspace=Path('/home/epi13/Documents/Projects');environment=workspace/'mncs-environment'
counts={'git_processes':0,'python_source_reads':0,'source_bytes':0}
run=module.subprocess.run;read=Path.read_bytes

def counted_run(command,*args,**kwargs):
 if command and command[0]=='git':counts['git_processes']+=1
 return run(command,*args,**kwargs)
def counted_read(path):
 data=read(path)
 if path.suffix=='.py' and path.is_relative_to(environment):
  counts['python_source_reads']+=1;counts['source_bytes']+=len(data)
 return data
module.subprocess.run=counted_run;Path.read_bytes=counted_read
service=module.EnvironmentService(ControlConfig(workspace_root=workspace))
rows=[]
for index in range(6):
 before=dict(counts);t=time.perf_counter();pkg=service._pkg()
 rows.append({'iteration':index,'seconds':time.perf_counter()-t,**{k:counts[k]-before[k] for k in counts}})
if hasattr(service,'close'):service.close()
output.write_text(json.dumps({'source':str(source),'rows':rows,'user_cpu':resource.getrusage(resource.RUSAGE_SELF).ru_utime,'system_cpu':resource.getrusage(resource.RUSAGE_SELF).ru_stime,'max_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss},indent=2)+'\n')
print(output.read_text())
