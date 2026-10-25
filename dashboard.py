"""AIRGUARD desktop dashboard for the passive AWID3 WIDS prototype.

Uses only Tkinter from Python's standard library. The replay button scores
held-out AWID3 windows offline; it never transmits or captures Wi-Fi frames.
"""
from __future__ import annotations
import json
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk
from datetime import datetime
from pathlib import Path

ROOT=Path(__file__).resolve().parent
METRICS=ROOT/'metrics.json'
ALERTS=ROOT/'alerts.jsonl'
COLORS={'bg':'#0a1420','panel':'#122231','panel2':'#172b3c','line':'#2a4052',
        'text':'#edf4f8','muted':'#9aabba','teal':'#35d0bd','orange':'#ff9a66',
        'green':'#123e3a','red':'#42271f','blue':'#6ca9ff'}

class AirguardDashboard:
    def __init__(self,root):
        self.root=root
        self.busy=False
        root.title('AIRGUARD | Passive Wi-Fi IDS')
        root.geometry('1280x880')
        root.minsize(980,700)
        root.configure(bg=COLORS['bg'])
        self.style=ttk.Style(root)
        self.style.theme_use('clam')
        self.style.configure('Treeview',background=COLORS['panel2'],foreground=COLORS['text'],
          fieldbackground=COLORS['panel2'],rowheight=28,borderwidth=0)
        self.style.configure('Treeview.Heading',background=COLORS['panel'],foreground=COLORS['muted'],
          font=('Segoe UI',9,'bold'),relief='flat')
        self.style.map('Treeview',background=[('selected','#1d615b')])
        self.metrics=json.loads(METRICS.read_text(encoding='utf-8'))
        self._build()
        self.refresh_alerts()

    def panel(self,parent,padx=16,pady=14):
        return tk.Frame(parent,bg=COLORS['panel'],highlightbackground=COLORS['line'],
                        highlightthickness=1,padx=padx,pady=pady)

    def label(self,parent,text,size=11,color=None,bold=False,**kw):
        return tk.Label(parent,text=text,bg=kw.pop('bg',COLORS['panel']),
            fg=color or COLORS['text'],font=('Segoe UI',size,'bold' if bold else 'normal'),
            anchor=kw.pop('anchor','w'),justify=kw.pop('justify','left'),**kw)

    def _build(self):
        shell=tk.Frame(self.root,bg=COLORS['bg']);shell.pack(fill='both',expand=True)
        sidebar=tk.Frame(shell,bg='#0d1b28',width=220,padx=14,pady=20)
        sidebar.pack(side='left',fill='y');sidebar.pack_propagate(False)
        self.workspace=tk.Frame(shell,bg=COLORS['bg']);self.workspace.pack(side='left',fill='both',expand=True)
        tk.Label(sidebar,text='AIRGUARD',bg='#0d1b28',fg=COLORS['teal'],font=('Segoe UI',17,'bold')).pack(anchor='w',pady=(0,2))
        tk.Label(sidebar,text='WIRELESS SECURITY',bg='#0d1b28',fg=COLORS['muted'],font=('Segoe UI',8,'bold')).pack(anchor='w',pady=(0,24))
        self.nav_buttons={}
        for title,detail,key in [('Overview','Model health and results','overview'),('Offline replay','Score held-out AWID3','replay'),('Alert history','Review local detections','alerts'),('Model & data','Features and limitations','model')]:
            button=tk.Button(sidebar,text=f'{title}\n{detail}',command=lambda k=key:self.show_page(k),bg='#163044',fg=COLORS['text'],activebackground='#1d615b',activeforeground='white',relief='flat',anchor='w',justify='left',font=('Segoe UI',10,'bold'),padx=12,pady=11,cursor='hand2')
            button.pack(fill='x',pady=4);self.nav_buttons[key]=button
        tk.Frame(sidebar,bg=COLORS['line'],height=1).pack(fill='x',pady=(18,10))
        tk.Label(sidebar,text='PASSIVE MODE\nNo Wi-Fi frames are transmitted.\nAlerts are logged locally.',bg='#0d1b28',fg=COLORS['teal'],justify='left',anchor='w',font=('Segoe UI',9),wraplength=185).pack(anchor='w')
        main=tk.Frame(self.workspace,bg=COLORS['bg'],padx=24,pady=20);main.pack(fill='both',expand=True)
        self.main_view=main
        head=tk.Frame(main,bg=COLORS['bg']);head.pack(fill='x',pady=(0,18))
        tk.Frame(head,bg=COLORS['teal'],width=6,height=62).pack(side='left',fill='y',padx=(0,14))
        htext=tk.Frame(head,bg=COLORS['bg']);htext.pack(side='left')
        self.label(htext,'AIRGUARD  /  LOCAL WIDS CONSOLE',10,COLORS['teal'],True,bg=COLORS['bg']).pack(anchor='w')
        self.label(htext,'Wireless intrusion detection',25,COLORS['text'],True,bg=COLORS['bg']).pack(anchor='w',pady=(3,0))
        tk.Label(head,text='OFFLINE DEMO  •  NO RADIO TX',bg='#103b37',fg='#9ef1e5',
          font=('Segoe UI',9,'bold'),padx=14,pady=9).pack(side='right',anchor='n')
        self.label(main,'AWID3 deauthentication windows · class-balanced Random Forest · validation-tuned threshold',
          10,COLORS['muted'],bg=COLORS['bg']).pack(anchor='w',pady=(0,12))

        cards=tk.Frame(main,bg=COLORS['bg']);cards.pack(fill='x',pady=(0,14))
        for i,(name,key,color) in enumerate([
          ('ACCURACY','accuracy',COLORS['teal']),('PRECISION','precision',COLORS['teal']),
          ('RECALL','recall',COLORS['orange']),('F1 SCORE','f1',COLORS['teal'])]):
            card=self.panel(cards,14,10);card.grid(row=0,column=i,sticky='nsew',padx=(0 if i==0 else 10,0))
            cards.grid_columnconfigure(i,weight=1)
            self.label(card,name,9,COLORS['muted'],True).pack(anchor='w')
            self.label(card,f"{self.metrics[key]*100:.1f}%",23,color,True).pack(anchor='w',pady=(2,0))

        mid=tk.Frame(main,bg=COLORS['bg']);mid.pack(fill='both',expand=True,pady=(0,14))
        left=self.panel(mid);left.pack(side='left',fill='both',expand=True,padx=(0,8))
        right=self.panel(mid);right.pack(side='left',fill='both',expand=True,padx=(8,0))
        self.label(left,'HELD-OUT CONFUSION MATRIX',11,COLORS['text'],True).pack(anchor='w')
        self.label(left,'Actual rows · predicted columns · normal / deauthentication',9,COLORS['muted']).pack(anchor='w',pady=(3,10))
        self._draw_matrix(left)
        self.label(left,f"Threshold {self.metrics['threshold']:.3f}  ·  {self.metrics['test_windows']} test windows",
          10,COLORS['muted'],True).pack(anchor='w',pady=(8,0))
        self.label(right,'FEATURE IMPORTANCE',11,COLORS['text'],True).pack(anchor='w')
        self.label(right,'Random Forest impurity importance',9,COLORS['muted']).pack(anchor='w',pady=(3,5))
        self.chart=tk.Canvas(right,bg=COLORS['panel'],highlightthickness=0,height=260)
        self.chart.pack(fill='both',expand=True)
        self.chart.bind('<Configure>',lambda e:self.draw_features())

        lower=tk.Frame(main,bg=COLORS['bg']);lower.pack(fill='both',expand=True)
        demo=self.panel(lower);demo.pack(fill='x',pady=(0,12))
        self.label(demo,'SAFE OFFLINE REPLAY',11,COLORS['text'],True).pack(anchor='w')
        self.label(demo,'Score two held-out AWID3 windows. An attack alert is appended to alerts.jsonl; no Wi-Fi traffic is sent.',
          9,COLORS['muted']).pack(anchor='w',pady=(3,9))
        controls=tk.Frame(demo,bg=COLORS['panel']);controls.pack(fill='x')
        self.replay_button=tk.Button(controls,text='Replay held-out windows',command=self.run_replay,
          bg=COLORS['teal'],fg='#06231f',activebackground='#71e5d7',activeforeground='#06231f',
          relief='flat',font=('Segoe UI',10,'bold'),padx=14,pady=8,cursor='hand2')
        self.replay_button.pack(side='left')
        self.status=self.label(controls,'Ready',9,COLORS['muted']);self.status.pack(side='left',padx=12)
        self.output=tk.Text(demo,height=3,bg='#08111b',fg='#b9f0e6',insertbackground='white',
          relief='flat',font=('Consolas',9),wrap='word',padx=9,pady=6)
        self.output.pack(fill='x',pady=(10,0));self.output.insert('1.0','Replay output appears here.')
        self.output.configure(state='disabled')

        logs=self.panel(lower);logs.pack(fill='both',expand=True)
        titlebar=tk.Frame(logs,bg=COLORS['panel']);titlebar.pack(fill='x',pady=(0,8))
        self.label(titlebar,'RECENT ALERTS',11,COLORS['text'],True).pack(side='left')
        self.label(titlebar,'Passive WIDS · logs only',9,COLORS['teal'],True).pack(side='right')
        self.tree=ttk.Treeview(logs,columns=('kind','source','window','score','time'),show='headings',height=4)
        for col,title,width in [('kind','EVENT',150),('source','SOURCE',235),('window','WINDOW / MAC',230),('score','P(ATTACK)',110),('time','TIME',220)]:
            self.tree.heading(col,text=title);self.tree.column(col,width=width,anchor='w')
        self.tree.pack(fill='both',expand=True)
        foot=tk.Frame(main,bg=COLORS['bg']);foot.pack(fill='x',pady=(10,0))
        self.label(foot,'Optional authorized capture: python wids.py capture --interface wlan0mon --seconds 60',
          9,COLORS['muted'],bg=COLORS['bg']).pack(side='left')
        self.label(foot,'Monitor only · no injection or blocking',9,COLORS['teal'],True,bg=COLORS['bg']).pack(side='right')
        self._make_extra_pages()

    def show_page(self,key):
        for page in self.pages.values():page.pack_forget()
        self.pages[key].pack(fill='both',expand=True)
        for name,button in self.nav_buttons.items():
            button.configure(bg='#1d615b' if name==key else '#163044')
        if key=='alerts':self.refresh_alerts()

    def _make_extra_pages(self):
        self.pages={'overview':self.main_view}
        replay=tk.Frame(self.workspace,bg=COLORS['bg'],padx=24,pady=22);self.pages['replay']=replay
        self.label(replay,'Offline replay',24,COLORS['text'],True,bg=COLORS['bg']).pack(anchor='w')
        self.label(replay,'Score saved, held-out AWID3 windows with the trained Random Forest. This demo does not access a Wi-Fi radio.',11,COLORS['muted'],bg=COLORS['bg'],wraplength=800).pack(anchor='w',pady=(6,20))
        panel=self.panel(replay,20,18);panel.pack(fill='x')
        self.label(panel,'SAFE OFFLINE DEMONSTRATION',11,COLORS['teal'],True).pack(anchor='w')
        self.label(panel,'A normal example and a deauthentication example are scored. Any alert is appended to alerts.jsonl.',10,COLORS['muted'],wraplength=800).pack(anchor='w',pady=(5,12))
        row=tk.Frame(panel,bg=COLORS['panel']);row.pack(fill='x')
        self.replay_button2=tk.Button(row,text='Run offline replay',command=self.run_replay,bg=COLORS['teal'],fg='#06231f',activebackground='#71e5d7',relief='flat',font=('Segoe UI',10,'bold'),padx=14,pady=9,cursor='hand2')
        self.replay_button2.pack(side='left')
        self.replay_status=self.label(row,'Ready',9,COLORS['muted']);self.replay_status.pack(side='left',padx=12)
        self.replay_output=tk.Text(panel,height=8,bg='#08111b',fg='#b9f0e6',insertbackground='white',relief='flat',font=('Consolas',10),wrap='word',padx=10,pady=8)
        self.replay_output.pack(fill='x',pady=(14,0));self.replay_output.insert('1.0','Replay output will appear here.');self.replay_output.configure(state='disabled')
        self.label(replay,'Alert storage',13,COLORS['text'],True,bg=COLORS['bg']).pack(anchor='w',pady=(24,6))
        self.label(replay,'Detections are saved locally in alerts.jsonl. Visit Alert history to review them.',10,COLORS['muted'],bg=COLORS['bg']).pack(anchor='w')

        alerts=tk.Frame(self.workspace,bg=COLORS['bg'],padx=24,pady=22);self.pages['alerts']=alerts
        self.label(alerts,'Alert history',24,COLORS['text'],True,bg=COLORS['bg']).pack(anchor='w')
        self.label(alerts,'Recent passive WIDS deauthentication detections recorded on this machine.',11,COLORS['muted'],bg=COLORS['bg']).pack(anchor='w',pady=(6,18))
        logpanel=self.panel(alerts);logpanel.pack(fill='both',expand=True)
        self.label(logpanel,'LOCAL JSONL EVENT LOG',11,COLORS['teal'],True).pack(anchor='w',pady=(0,10))
        self.alert_tree=ttk.Treeview(logpanel,columns=('kind','source','window','score','time'),show='headings',height=15)
        for col,title,width in [('kind','EVENT',150),('source','SOURCE',180),('window','WINDOW / MAC',200),('score','P(ATTACK)',110),('time','TIME',190)]:
            self.alert_tree.heading(col,text=title);self.alert_tree.column(col,width=width,anchor='w')
        self.alert_tree.pack(fill='both',expand=True)
        tk.Button(logpanel,text='Refresh alerts',command=self.refresh_alerts,bg='#163044',fg=COLORS['text'],relief='flat',font=('Segoe UI',9,'bold'),padx=12,pady=7,cursor='hand2').pack(anchor='e',pady=(10,0))

        model=tk.Frame(self.workspace,bg=COLORS['bg'],padx=24,pady=22);self.pages['model']=model
        self.label(model,'Model & data',24,COLORS['text'],True,bg=COLORS['bg']).pack(anchor='w')
        self.label(model,'An explainer for the prototype and how to interpret its results.',11,COLORS['muted'],bg=COLORS['bg']).pack(anchor='w',pady=(6,18))
        info=self.panel(model,20,18);info.pack(fill='x')
        sections=[('CLASSIFIER','Class-balanced Random Forest. The alert threshold is selected on validation data, then evaluated on a chronological held-out tail.'),('INPUT FEATURES','Normalized frame length and RSSI; management-frame fraction; deauthentication count per 100 frames and peak over 10 frames; retry and protected fractions; subtype diversity; frame-type entropy.'),('DATA AND LIMITS','2,279 preprocessed AWID3 windows from one source capture. This is a prototype benchmark, not a guarantee of field performance. The CSV has no timestamps, so frame rate is counted per 100 frames, not per second. Optional live capture is receive-only and requires an authorized monitor-mode setup.'),('SAFETY','This is a WIDS that observes and logs. It does not transmit management frames or block devices.')]
        for title,body in sections:
            self.label(info,title,10,COLORS['teal'],True).pack(anchor='w',pady=(0,4))
            self.label(info,body,11,COLORS['text'],wraplength=820).pack(anchor='w',pady=(0,16))
        self.show_page('overview')

    def _draw_matrix(self,parent):
        cm=self.metrics['confusion_matrix']
        grid=tk.Frame(parent,bg=COLORS['panel']);grid.pack(fill='x',pady=2)
        tk.Label(grid,text='PREDICTED',bg=COLORS['panel'],fg=COLORS['muted'],font=('Segoe UI',8,'bold')).grid(row=0,column=1,columnspan=2,pady=(0,4))
        for c,label in enumerate(['Normal','Deauth'],1):
            tk.Label(grid,text=label,bg=COLORS['panel'],fg=COLORS['muted'],font=('Segoe UI',9,'bold')).grid(row=1,column=c,padx=4,pady=(0,5))
        for r,label in enumerate(['ACTUAL NORMAL','ACTUAL ATTACK'],2):
            tk.Label(grid,text=label,bg=COLORS['panel'],fg=COLORS['muted'],font=('Segoe UI',8,'bold')).grid(row=r,column=0,sticky='e',padx=(0,6))
            for c in range(2):
                value=cm[r-2][c]
                correct=(r-2)==c
                color='#123d39' if correct else '#41271f'
                tk.Label(grid,text=str(value)+'\n'+('correct' if correct else ('false alert' if c==1 else 'missed attack')),
                  bg=color,fg=COLORS['teal'] if correct else COLORS['orange'],
                  font=('Segoe UI',15,'bold'),width=17,height=3).grid(row=r,column=c+1,padx=4,pady=4,sticky='nsew')
        for c in range(3):grid.grid_columnconfigure(c,weight=1)

    def draw_features(self):
        c=self.chart;c.delete('all')
        items=self.metrics['feature_importance'][:7]
        width=max(c.winfo_width(),400);left=190;bar_right=width-58;bar_w=max(50,bar_right-left)
        row_h=34
        for i,item in enumerate(items):
            y=18+i*row_h
            label=item['feature'].replace('_',' ')
            c.create_text(4,y+7,text=label,fill=COLORS['text'],anchor='w',font=('Segoe UI',8))
            c.create_rectangle(left,y,bar_right,y+11,fill='#2a3e4d',outline='')
            fraction=item['importance']/(items[0]['importance'] or 1)
            c.create_rectangle(left,y, left+bar_w*fraction,y+11,fill=COLORS['teal'],outline='')
            c.create_text(width-2,y+7,text=f"{item['importance']*100:.1f}%",fill=COLORS['muted'],anchor='e',font=('Segoe UI',8,'bold'))

    def set_output(self,text):
        self.output.configure(state='normal');self.output.delete('1.0','end')
        self.output.insert('1.0',text);self.output.configure(state='disabled')

    def run_replay(self):
        if self.busy:return
        self.busy=True;self.replay_button.configure(state='disabled')
        if hasattr(self,'replay_button2'):self.replay_button2.configure(state='disabled')
        self.status.configure(text='Scoring held-out AWID3 windows…',fg=COLORS['orange'])
        if hasattr(self,'replay_status'):self.replay_status.configure(text='Scoring AWID3 windows…',fg=COLORS['orange'])
        self.set_output('')
        def worker():
            try:
                p=subprocess.run([sys.executable,str(ROOT/'wids.py'),'replay'],cwd=ROOT,
                  capture_output=True,text=True,timeout=30)
                output=(p.stdout or '')+(p.stderr or '')
                self.root.after(0,self.finish_replay,p.returncode,output)
            except Exception as e:self.root.after(0,self.finish_replay,1,str(e))
        threading.Thread(target=worker,daemon=True).start()

    def finish_replay(self,code,output):
        self.busy=False;self.replay_button.configure(state='normal')
        if hasattr(self,'replay_button2'):self.replay_button2.configure(state='normal')
        self.status.configure(text='Replay complete' if code==0 else 'Replay failed',
          fg=COLORS['teal'] if code==0 else COLORS['orange'])
        self.set_output(output.strip() or 'No output returned.')
        if hasattr(self,'replay_status'):self.replay_status.configure(text='Replay complete' if code==0 else 'Replay failed',fg=COLORS['teal'] if code==0 else COLORS['orange'])
        if hasattr(self,'replay_output'):
            self.replay_output.configure(state='normal');self.replay_output.delete('1.0','end')
            self.replay_output.insert('1.0',output.strip() or 'No output returned.');self.replay_output.configure(state='disabled')
        self.refresh_alerts()

    def refresh_alerts(self):
        for tree in [getattr(self,'tree',None),getattr(self,'alert_tree',None)]:
            if tree:
                for item in tree.get_children():tree.delete(item)
        if not ALERTS.exists():return
        try:lines=ALERTS.read_text(encoding='utf-8').splitlines()[-8:]
        except OSError:return
        for line in reversed(lines):
            try:event=json.loads(line)
            except json.JSONDecodeError:continue
            stamp=event.get('timestamp_utc','')
            try:stamp=datetime.fromisoformat(stamp.replace('Z','+00:00')).astimezone().strftime('%m-%d %H:%M:%S')
            except Exception:pass
            macs=event.get('offending_macs',[])
            target=', '.join(str(x[0]) for x in macs[:2]) if macs else str(event.get('window_id','—'))
            score=event.get('probability',event.get('malicious_probability','—'))
            if isinstance(score,(int,float)):score=f'{score:.3f}'
            values=('DEAUTH ALERT',event.get('source','unknown'),target,score,stamp)
            for tree in [getattr(self,'tree',None),getattr(self,'alert_tree',None)]:
                if tree:tree.insert('', 'end',values=values)

def main():
    root=tk.Tk()
    AirguardDashboard(root)
    root.mainloop()

if __name__=='__main__':main()


