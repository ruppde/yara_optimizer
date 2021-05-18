#!/usr/bin/env python3

# push all strings and conditions from private yara rules into the normal rules
# dirty write once hack. works for me but check the output!
# will drop some comments in conditions!

# by arnim rupp 

# License: GPLv3 or newer


import plyara

# !!!!!!!!!!!!!!! use plyara version after 23th April 2021 because of nasty bug https://github.com/plyara/plyara/issues/113 
import plyara.utils

import yara
import pprint
import argparse
import sys
import re
import os

# TODO: create option to include checking the extension to reuce FP for thor & loki. 
# however, webshells can in files with any extension if the webserver is configured accordingly, see e.g. those webshells in .png or in logfiles via a local file include vuln
ext={}
ext['asp'] = ['asp', 'aspx', 'asax', 'ashx', 'asmx']
ext['jsp'] = ['asp', 'java'] # could also search in zero-compression .war, .ear, ...
ext['php'] = ['php', 'cgi']  

priv_cond = {}
priv_strings = {}

new_yar = ""
verbose = False

def log(msg):
    if verbose:
        print(msg)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Yara private rule pusher')
    parser.add_argument('--debug', '-d', help='Debug', action='store_true')
    parser.add_argument('--force', '-f', help='Force, overwrite existing output file', action='store_true')
    parser.add_argument('--keep-comment', help='Keep comments in front of first rule', action='store_true')
    parser.add_argument('--keep-normal-rules', help='Also write normal rules which do not need changes to output file', action='store_true')
    parser.add_argument('--nowarning', '-n', help='Do not include warning in outfile', action='store_true')
    parser.add_argument('--verbose', '-v', help='Be verbose', action='store_true')
    parser.add_argument('--match', '-m', help='Only output rules which match this string in the rule name', default="")
    parser.add_argument('--exclude', '-e', help='Exclude rules which match this string in the rule name', default="impossible_string_shoulnt_match_on_anything_blblblblbl")
    parser.add_argument("yarfile", help=".yar file")

    args = parser.parse_args()
    yarfile = args.yarfile
    verbose = args.verbose
    debug = args.debug
    nowarning = args.nowarning
    keep_normal_rules = args.keep_normal_rules
    match = args.match
    exclude = args.exclude

    parser = plyara.Plyara()

    try:
        with open(yarfile, 'r') as fh:
            data = fh.read()
    except Exception as e:
        print("Error:", e)
        sys.exit(0)
    print("Parsing yara file: " + yarfile)

    postfix = '_no_private_rules'
    if match:
        postfix += '__' + match
    outfile = re.sub(r'(\.yara?)', postfix + '\g<1>', yarfile )
    new_rules = ""

    if os.path.exists(outfile) and not args.force:
        print("\nERROR: output file already exists: " + outfile + "   \nUse --force to overwrite\n")
        sys.exit(0)

    # print big comment before the rules
    if args.keep_comment:
        r = re.search(r'/\*.+?\*/', data, re.DOTALL)
        if r:
            log(r.group(0))
            new_rules += (r.group(0) + '\n\n')
        

    try:
        rules_dict = parser.parse_string(data)
    except Exception as e:
        print("Error:", e)
        sys.exit(0)

    if debug:
        pprint.pprint(rules_dict)

    rule_imports = []
    rule_count = 0
    rule_count_priv = 0
    rule_count_dep = 0
    rule_count_out = 0
    for rule in rules_dict:
        log("----------------- doing rule: "+ rule['rule_name'])

        # handle imports 
        if 'imports' in rule:
            # collect imports to print them in front of final rules output
            imports = rule['imports']
            if debug:
                print("imports: ", imports)
            for imp in imports:
                if not imp in rule_imports:
                    rule_imports.append(imp)
            # remove for plyara or it would be printed before each rule
            rule['imports'] = ''

        # private rules must be before normal rules referencing them, but that's required in yara anyway
        if 'scopes' in rule and 'private' in rule['scopes']:
            rule_count_priv += 1
            log("doing private rule: "+ rule['rule_name'])


            if 'strings' in rule:
                # [1:] to skip first line which only contains "strings:"
                if re.search(r'\$[\t ]*?=', rule['raw_strings']):
                    print("ERROR: anonymous string in " + rule['rule_name'] + " and I don't know how to handle it. Either change the rule(s) or this script ;)")
                    sys.exit()

                priv_strings[rule['rule_name']] = '\t\t//strings from private rule ' + rule['rule_name'] + '\n' + '\n'.join(rule['raw_strings'].splitlines()[1:])
                log("strings:\n" + priv_strings[rule['rule_name']])

            if 'raw_condition' in rule:
                # [1:] to skip first line which only contains "condition:"
                lines = rule['raw_condition'].splitlines()[1:]
                log("LINES:" + repr(lines) )
                lines = [re.sub(r'\t\t', '\t\t\t', i) for i in lines]
                priv_cond[rule['rule_name']] = '\n' + '\n'.join(lines)
                log("cond:" + priv_cond[rule['rule_name']])
        else:
            # normal rule

            if debug:
                pprint.pprint(plyara.utils.detect_dependencies(rule))

            new_str = ""
            if 'raw_strings' in rule:
                new_str = rule['raw_strings']

            if not plyara.utils.detect_dependencies(rule):
                # not priv used, could just use old rule
                rule_count += 1

                if keep_normal_rules and match in rule['rule_name'] and not exclude in rule['rule_name']:
                    log("START ONEW")
                    log(plyara.utils.rebuild_yara_rule(rule))
                    new_rules += (plyara.utils.rebuild_yara_rule(rule) +'\n')
                    rule_count_out += 1
                    log("END ONEW")
            else:
                # rule which depends on private rules
                rule_count_dep += 1

                # in conditions replace rule reference with private rules conditions
                new_cond = ""
                log("----RAWCOND: " + rule['raw_condition'])
                linebreak = False
                for condition in rule['condition_terms']:
                    if linebreak and ( condition == '(' or condition == ')' ):
                        new_cond += '\n\t\t'
                    linebreak = False
                    log("----COND: " + condition)
                    if condition in priv_cond:
                        log("reference to private rule: " + condition)
                        new_cond += '( ' + priv_cond[condition] + ' \n\t\t)\n\t\t'
                    else:
                        if condition == 'or' or condition == 'and':
                            linebreak = True

                        new_cond += condition + ' '

                    # add strings from private rule
                    if condition in priv_strings:
                        new_str += '\n' + priv_strings[condition]

                log("new_cond: " + new_cond)
                log("new_str: " + new_str)

                log("START OLD")
                log(plyara.utils.rebuild_yara_rule(rule))
                log("END OLD")
                rule['condition_terms'] = new_cond
                log("START NEW")
                log(plyara.utils.rebuild_yara_rule(rule))
                log("END NEW")

                # built rule out of dict
                after_cond_rule = plyara.utils.rebuild_yara_rule(rule)

                # now old fashioned go over lines and add new strings from private rules
                new_rule = ""
                in_strings=False
                in_strings_ever=False
                for line in after_cond_rule.splitlines():
                    #print("LINE", line)
                    if re.search(r'condition:$', line):
                        if in_strings_ever==False:
                            # no strings: in normal rule
                            new_rule += "\tstrings:\n" + new_str + '\n'

                        in_strings=False

                        # now print the "condition:"
                        new_rule += line + '\n'#\t\t\tXX'
                    elif re.search(r'strings:$', line):
                        log("WW-------------------")
                        new_rule += '\t' + new_str + '\n'
                        in_strings=True
                        in_strings_ever=True
                    elif in_strings:
                        # drop strings: line, already there
                        pass
                    else:
                        # any other line
                        new_rule += line + '\n'

                if match in rule['rule_name'] and not exclude in rule['rule_name']:
                    log("START NNEW")
                    log(new_rule)
                    new_rules += new_rule +'\n'
                    rule_count_out += 1
                    log("END NNEW")


            if debug:
                pprint.pprint(rule)
            log("-----")


    print('In:  Number of normal rules:                                         {}'.format(rule_count))
    print('In:  Number of normal rules which where depeneded on privates rules: {}'.format(rule_count_dep))
    print('In:  Number of private rules:                                        {}'.format(rule_count_priv))
    print('In:  Number of rules total:                                          {}'.format(rule_count + rule_count_dep + rule_count_priv))
    print('Out: Number of rules:                                                {}'.format(rule_count_out))

    if rule_count_out != ( rule_count + rule_count_dep ) and not match and not exclude:
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("ERROR: Number of out-rules don't match up in-rules.")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    else:
        print("OK: Number of out-rules matches non-private in-rules.")

    if not new_rules:
        print("No private rules found, no output file created")
    else:
        try:
            yarout = open(outfile, 'w')
        except Exception as e:
            print("Error:", e)
            sys.exit(0)

        if not nowarning:
            yarout.write("// Rules converted using yara_push_private_rules.py\n")
            yarout.write("// BEWARE of dropped comments in the rules!!!\n") 
        #yarout.write("// This file just contains the rules, which where dependent on private rules in " + yarfile + "\n\n") 
        for imp in rule_imports:
            new_rules = "import \""+ imp + "\"\n" + new_rules

        # do syntax check using yara-python
        try:
            y = yara.compile(source=new_rules, externals={
                        'filename': "",
                        'filepath': "",
                        'extension': "",
                        'filetype': "",
                        'md5': "",
                    })
            print("Rule syntax OK")
        except Exception as e:
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("ERROR: ", e)
            #print("Yep, this code doesn't handle duplicate strings. Either change it in the rules or improve this code.")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")

        yarout.write(new_rules)
        print("Created new file: " + outfile)
        print("BEWARE: Beta code, check your rules!! (E.g. scan a malware stash with old and new rules and compare the number of findings.)")
        print("BEWARE: removes some of the comments!! (needs fix in plyara)")
