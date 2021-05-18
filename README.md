

# YARA push private rules

This script pushes the strings and conditions of private rules into all standard rules using them and drops the private rules.

The advantage of private rules are, that they reduce redundancy during rules creation, like a function or subroutine in programming. The drawbacks are, that you don't see the matched strings anymore. You could remove the "private" and reference them as normal rules but then you still get a lot of matches you don't want to see, unless all conditions of the parent rule are satistied. 
This script solves all these problems by allowing the usage of private rules during developemt but resolving them before using the rules in real life.



## Example

Rules before
```YARA
private rule capa_php_input {
	meta:
		description = "PHP user input methods"
	strings:
		$inp2 = "_GET["
		$inp3 = "_POST["
		$inp5 = "_SERVER['HTTP_"
	condition:
		any of ( $inp* )
}

private rule capa_php_payload {
	meta:
		description = "PHP methods for executing OS commands or eval"
	strings:
		$cpayload1 = /\beval[\t ]*\([^)]/
		$cpayload9 = /\bassert[\t ]*\([^)]/
		$cpayload10 = /\bpreg_replace[\t ]*\([^\)]1,1000}\/e/
	condition:
		any of ( $cpayload* )
}

rule webshell_php_generic_tiny {
	meta:
		description = "PHP webshell having some kind of input and some kind of payload."
	condition:
		filesize < 1000 
		and capa_php_input
		and capa_php_payload
}
```

Rule after:
```YARA
rule webshell_php_generic_tiny
{
	meta:
		description = "PHP webshell having some kind of input and some kind of payload."

	strings:

		//strings from private rule capa_php_input
		$inp2 = "_GET["
		$inp3 = "_POST["
		$inp5 = "_SERVER['HTTP_"
	
		//strings from private rule capa_php_payload
		$cpayload1 = /\beval[\t ]*\([^)]/
		$cpayload9 = /\bassert[\t ]*\([^)]/
		$cpayload10 = /\bpreg_replace[\t ]*\([^\)]1,1000}\/e/
	
	condition:
		filesize < 1000 and ( 
			any of ( $inp* ) 
		)
		and ( 
			any of ( $cpayload* ) 
		)
		
}
```

## Install

Required modules are yara-python and plyara version with https://github.com/plyara/plyara/pull/114 due to a bug before that.


No installation is 

## Usage
```bash
usage: yara_push_private_rules.py [-h] [--force] [--verbose] [--debug]
                                  [--keep-comment]
                                  yarfile

Yara private rule pusher

positional arguments:
  yarfile         .yar file

optional arguments:
  -h, --help      show this help message and exit
  --force         Force, overwrite existing output file
  --verbose       Be verbose
  --debug         Debug
  --keep-comment  Keep comments

```

Todo:
- [ ] Handle anonymous strings ( $ = "" )
- [ ] Duplicate strings
- [ ] Rules nested more than one layer

## License
GNU General Public License v3.0

## Author

arnim rupp
