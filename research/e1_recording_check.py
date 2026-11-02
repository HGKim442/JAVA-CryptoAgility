"""Induced weakness in a private fixture copy proves successful PROPOSED attacks are recorded."""
import csv,json,pathlib,subprocess,tempfile,hashlib
BASE=pathlib.Path(__file__).resolve().parents[1]
source=BASE/'research/e1/E1Experiment.java'
with tempfile.TemporaryDirectory(prefix='e1-recorder-control-') as tmp:
 p=pathlib.Path(tmp);altered=source.read_text().replace('new Pipeline(mode,f.store)','new Pipeline(mode==Mode.PROPOSED?Mode.VULNERABLE:mode,f.store)');(p/'E1Experiment.java').write_text(altered)
 subprocess.run(['java','-m','jdk.compiler/com.sun.tools.javac.Main','--release','17','-Xlint:all','-Werror','-cp',str(BASE/'build'),'-d',str(p),str(p/'E1Experiment.java')],check=True)
 subprocess.run(['java','-Xmx512m','-cp',str(p)+':'+str(BASE/'build'),'E1Experiment',str(p/'observations'),'1'],check=True)
 with (p/'observations/attacks.csv').open(newline='') as stream:rows=list(csv.DictReader(stream))
 assert len(rows)==90
 selected=[r for r in rows if r['mode']=='PROPOSED'];assert len(selected)==30 and all(r['attack_effect']=='true' and r['blocked']=='false' for r in selected)
 result={'passed':True,'induced_proposed_attack_effect_rows_recorded':30,'total_rows':90,'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'scope':'Private altered fixture only; demonstrates recorder does not abort/suppress successful attacks. Not measured proposed-implementation security evidence.'}
 out=BASE/'results/security/e1-recording-check.json';out.write_text(json.dumps(result,indent=2)+'\n');print('PASS E1 recorder retains induced attack successes=30')
