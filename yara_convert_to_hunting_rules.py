#!/usr/bin/env python3

# convert normal yara rules to hunting rules (more hits but also more false positives) by:
# 1. increasing filesize (while not hitting on smaller files because the normal rules already do that)
# 2. removing $fp strings
# 3. changing/setting score = 40
# 4. append __converted_to_hunting to rule name
# 5. add PROD tag to HUNT_CONVERTED
# 6. remove all hashes from meta:

# TODO:
# - increase size of e.g.
#                $php_short in (0..100) or
#                $php_short in (filesize-1000..filesize)
#  ... without breaking:
#                math.mean(500, filesize-500) > 80 and
# TODO: measure FP from goodware

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
from time import strftime,gmtime

now = strftime("%Y-%m-%d %H:%M:%S", gmtime())

verbose = False

def log(msg):
    if verbose:
        print(msg)

def increase_size( size, factor ):
    r = re.search(r'(\d+)(.*)', size)
    size_old  = int( r.group(1) )
    unit      = r.group(2)

    size_new = size_old * factor
    return str(size_new) + unit


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Yara hunting rule converter')
    parser.add_argument('--debug', '-d', help='Debug', action='store_true')
    parser.add_argument('--force', '-f', help='Force, overwrite existing output file', action='store_true')
    parser.add_argument('--keep-comment', help='Keep comments in front of first rule', action='store_true')
    parser.add_argument('--nowarning', '-n', help='Do not include warning in outfile', action='store_true')
    parser.add_argument('--verbose', '-v', help='Be verbose', action='store_true')
    parser.add_argument('--match', '-m', help='Only output rules which match this string', default="")
    parser.add_argument('--increase_factor', '-i', help='Factor to increase filesize conditions, default is 3', default=3)
    parser.add_argument("yarfile", help=".yar file")

    args = parser.parse_args()
    yarfile = args.yarfile
    verbose = args.verbose
    debug = args.debug
    nowarning = args.nowarning
    match = args.match
    increase_factor = int( args.increase_factor )

    parser = plyara.Plyara()

    try:
        with open(yarfile, 'r') as fh:
            data = fh.read()
    except Exception as e:
        print("Error:", e)
        sys.exit(0)
        
    print("Parsing yara file: " + yarfile)

    postfix = '__converted_to_hunting'
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
    rule_count_increased = 0
    rule_count_already_hunt = 0
    rule_count_skipped = 0

    for rule in rules_dict:

        rule_count += 1
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

        if 'PROD' in rule['tags']:
            for index, item in enumerate(rule['tags']):
                if item == 'PROD':
                    rule['tags'][index] = 'HUNT_CONVERTED'

        if '_hunting_' in rule['rule_name']:
            log("hunting rule, just add it: "+ rule['rule_name'])
            new_rules += (plyara.utils.rebuild_yara_rule(rule) +'\n')
            rule_count_already_hunt += 1

        else:
            # normal rules which needs to be converted:

            ############# convert meta: ###############################

            rule['rule_name'] = rule['rule_name'] + '__converted_for_hunting'

            # add/change score = 40 for thor & loki
            new_meta = []
            score_already_there = False
            for meta in rule['metadata']:
                print(meta)
                key, value = list(meta.items())[0]
                if key == 'score':
                    log("META: "+ repr(meta))
                    tmp_meta = {}
                    tmp_meta['score'] = 40
                    new_meta.append( tmp_meta )

                    score_already_there = True
                elif key == 'hash':
                    # drop all hashes because the converted rules shouldn't them anymore due to new minimum size
                    pass
                else:
                    tmp_meta = {}
                    tmp_meta['key'] = value
                    new_meta.append( tmp_meta )

            if not score_already_there:
                tmp_meta = {}
                tmp_meta['score'] = 40
                new_meta.append( tmp_meta )

            # replace old meta: section with new one
            rule['metadata'] = new_meta
            log("new_meta: " + repr( new_meta ))
            log(plyara.utils.rebuild_yara_rule(rule))

            ############# convert conditions: #########################
            conditions = rule['condition_terms']
            new_cond = ""
            sizelimit = False

            if 'filesize' in conditions:
                print("rule with filesize:" )

                log("----RAWCOND: " + rule['raw_condition'])
                linebreak = False

                num_cond = 0
                cond = conditions[ num_cond ]

                #for condition in rule['condition_terms']:
                while num_cond < len(conditions):
                    condition = conditions[ num_cond ]
                    num_cond += 1

                    if linebreak and ( condition == '(' or condition == ')' ):
                        new_cond += '\n\t\t'
                    linebreak = False
                    log("----COND: " + condition)

                    if condition == 'filesize':
                        log("filesize condition: " + condition)

                        next_cond = conditions[ num_cond ] 
                        num_cond += 1
                        if next_cond == "<" :
                            log("----COND<>: " + condition)
                            sizelimit = True
                            operator = next_cond
                            size_old = conditions[ num_cond ]
                            size_new = increase_size( size_old, increase_factor )
                            num_cond += 1
                            new_cond += '( filesize >= ' + size_old + ' and filesize < ' + size_new + ' \n\t\t)\n\t\t'
                        else:
                            new_cond += condition + ' ' + next_cond + ' '
                    else:
                        if condition == 'or' or condition == 'and':
                            linebreak = True

                        new_cond += condition + ' '



                log("new_cond: " + new_cond)

                log("START OLD")
                log(plyara.utils.rebuild_yara_rule(rule))
                log("END OLD")
                rule['condition_terms'] = new_cond
                log("START NEW")
                log(plyara.utils.rebuild_yara_rule(rule))
                log("END NEW")

                # built rule out of dict
                after_cond_rule = plyara.utils.rebuild_yara_rule(rule)

                # now old fashioned go over lines and add strings (advantage over plyara way: keeps comments)
                # TODO: remove?
                new_rule = ""
                in_strings=False
                in_strings_ever=False
                for line in after_cond_rule.splitlines():
                    if re.search(r'condition:$', line):

                        # now print the "condition:"
                        new_rule += line + '\n'#\t\t\tXX'
                    else:
                        # any other line
                        print("LINE", line)
                        new_rule += line + '\n'

                if not sizelimit:
                    print("rule WITHOUT sizelimit, skipping because it would produce the same results as the original rules: ", rule['rule_name'] )
                    rule_count_skipped += 1
                elif match in rule['rule_name']:
                    log("START NNEW")
                    log(new_rule)
                    new_rules += new_rule +'\n'
                    rule_count_increased += 1
                    log("END NNEW")


        if debug:
            pprint.pprint(rule)
        log("-----")


    print('In     : Number of rules:                                                                        {}'.format(rule_count))
    print('Out    : Number of converted rules:                                                              {}'.format(rule_count_increased))
    print('Out    : Number of already hunting rules:                                                        {}'.format(rule_count_already_hunt))
    print('Skipped: Number of skipped rules because no size limit (would produce same results as original): {}'.format(rule_count_skipped))

    if rule_count_increased + rule_count_already_hunt + rule_count_skipped != rule_count and not match:
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("ERROR: Number of out-rules don't match up in-rules.")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    else:
        print("OK: Number of out-rules matches in-rules.")

    if not new_rules:
        print("No rules found, no output file created")
    else:
        try:
            yarout = open(outfile, 'w')
        except Exception as e:
            print("Error:", e)
            sys.exit(0)

        if not nowarning:
            yarout.write("// Rules converted using yara_convert_to_hunting_rules.py on " + now + "\n")
            yarout.write("// Use in conjunction with https://github.com/2d4d/signature-base/blob/master/yara/gen_webshells.yar" + now + "\n")
            yarout.write("// Original rules from: " + yarfile +"\n") 
            yarout.write("// Factor of 'filesize' conditions increase: " + str(increase_factor) +"\n") 
            yarout.write("// Number of converted rules: " + str(rule_count_increased) +"\n") 
            yarout.write("// Number of already hunting rules: " + str(rule_count_already_hunt) +"\n") 
            yarout.write("// BEWARE of dropped comments in the rules after converting!!!\n\n") 

        imp_tmp = ""
        for imp in rule_imports:
            imp_tmp += "import \""+ imp + "\"\n" 
            
        new_rules = imp_tmp + '\n' + new_rules

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
