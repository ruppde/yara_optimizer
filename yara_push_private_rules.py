#!/usr/bin/env python3

# push all strings and conditions from private yara rules into the normal rules

# by arnim rupp 

# License: GPLv3 or newer


import plyara
import plyara.utils
import yara
import pprint
import argparse
import sys
import re
import os


priv_cond = {}
priv_strings = {}

new_yar = ""
verbose = False

def log(msg):
    if verbose:
        print(msg)

def main():

    parser = argparse.ArgumentParser(description='Yara private rule pusher')
    parser.add_argument('--force', help='Force, overwrite existing output file', action='store_true')
    parser.add_argument('--verbose', help='Be verbose', action='store_true')
    parser.add_argument('--debug', help='Debug', action='store_true')
    parser.add_argument('--keep-comment', help='Keep comments', action='store_true')
    parser.add_argument("yarfile", help=".yar file")

    args = parser.parse_args()
    yarfile = args.yarfile
    verbose = args.verbose
    debug = args.debug

    parser = plyara.Plyara()


    try:
        with open(yarfile, 'r') as fh:
            data = fh.read()
    except Exception as e:
        print("Error:", e)
        sys.exit(0)
    print("Parsing yara file: " + yarfile)

    outfile = re.sub(r'(\.yara?)', '_no_private_rules\g<1>', yarfile )

    if os.path.exists(outfile) and not args.force:
        print("\nERROR: output file already exists: " + outfile + "   Use --force to overwrite\n")
        sys.exit(0)

    # print big comment before the rules
    if args.keep_comment:
        r = re.search(r'/\*.+?\*/', data, re.DOTALL)
        log(r.group(0))
        yarout.write(r.group(0) + '\n\n')
        

    try:
        rules_dict = parser.parse_string(data)
    except Exception as e:
        print("Error:", e)
        sys.exit(0)

    if debug:
        pprint.pprint(rules_dict)

    rule_count = 0
    rule_imports = []
    rule_count_priv = 0
    new_rules = ""
    for rule in rules_dict:


        # private rules must be before normal rules referencing them, but that's required in yara anyway
        if 'scopes' in rule and 'private' in rule['scopes']:
            rule_count_priv += 1
            log("doing private rule: "+ rule['rule_name'])

            # handle imports 
            if 'imports' in rule:
                # collect imports to print them in front of final rules output
                imports = rule['imports']
                print("imports: ", imports)
                for imp in imports:
                    if not imp in rule_imports:
                        rule_imports.append(imp)
                # remove for plyara or it would be printed before each rule
                rule['imports'] = ''

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
            rule_count += 1

            if debug:
                pprint.pprint(plyara.utils.detect_dependencies(rule))

            new_str = ""
            if 'raw_strings' in rule:
                new_str = rule['raw_strings']

            if not plyara.utils.detect_dependencies(rule):
                # not priv used, could just use old rule
                pass
                # if you change this, move the collection of the imports above outside of the private rules block! see "handle imports"

                # we could just write the rules as they are but this makes checking the converted rules for missing comments more complicated. 
                # lets wait until this code is good enough to handle all cases
                #log("START ONEW")
                #log(plyara.utils.rebuild_yara_rule(rule))
                #yarout.write(plyara.utils.rebuild_yara_rule(rule) +'\n')
                #log("END ONEW")
            else:
                # rule which depends on private rules

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

                # now old fashioned go over lines and add new strings from private rules (advantage over plyara way: keeps comments)
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
                log("START NNEW")
                log(new_rule)
                new_rules += new_rule +'\n'
                log("END NNEW")


            if debug:
                pprint.pprint(rule)
            log("-----")


    print('Number of normal rules in file: {}'.format(rule_count))
    print('Number of private rules in file: {}'.format(rule_count_priv))

    if not new_rules:
        print("No private rules found, no output file created")
    else:
        try:
            yarout = open(outfile, 'w')
        except Exception as e:
            print("Error:", e)
            sys.exit(0)

        yarout.write("// Rules converted using yara_push_private_rules.py")
        yarout.write("// BEWARE of dropped comments in the rules!!!\n") 
        yarout.write("// This file just contains the rules, which where dependent on private rules in " + yarfile + "\n\n") 
        for imp in rule_imports:
            yarout.write("import \""+ imp + "\"\n")
        yarout.write(new_rules)

        # do syntax check using yara-python
        try:
            y = yara.compile(source=new_rules, externals={
                        'filename': "",
                        'filepath': "",
                        'extension': "",
                        'filetype': "",
                        'md5': "",
                    })
        except Exception as e:
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("ERROR: ", e)
            print("Yep, this code doesn't handle duplicate strings. Either change it in the rules or improve this code.")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")

        print("Created new file: " + outfile)
        print("BEWARE: alpha code, check your rules!!")
        print("BEWARE: removes some of the comments!!")

if __name__ == "__main__":
    main()

