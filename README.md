msf-autoshell
------
Give it a .nessus file and it'll get you Metasploit shells. I've included the early and incomplete programs to make it easier for people who want to learn how to use the python-libnessus and msfrpc libraries. 
* `msf-autoshell-boilerplate.py` was the first step; a simple boilerplate program with some boring stuff filled out. 
* `msf-autoshell-parse-nessus.py` was the next step and all it does is parse the .nessus file and grab some info off the parsed objects. 
* `msf-autoshell-msfrpc-connect.py` shows how to connect to the Metasploit RPC server and some examples of interacting with it. 
* Finally, `msf-autoshell.py` is the final script with all the Metasploit logic code for running modules in it.

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

### Credits
Thanks to Coalfire for some development time.
