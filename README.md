msf-autoshell
------
Give it a .nessus file and it'll get you Metasploit shells. I've included the early and incomplete programs to make it easier for people who want to learn how to use the python-libnessus and msfrpc libraries. Boilerplate is 

#### Installation
This install is only tested on Kali.

```
git clone https://github.com/DanMcInerney/msf-autoshell
cd msf-autoshell
pipenv install --three
pipenv shell

In a new terminal: 
> msfconsole
msf > load msgrpc Pass=123
```

#### Usage
```python msf-autoshell.py -n /path/to/nessus/file.nessus```
