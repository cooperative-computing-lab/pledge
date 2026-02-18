import Levenshtein
import itertools

def sub_idx(indexes, name, token='$'):
    for i in indexes:
        name = name[:i] + f'{token}' + name[i+1:]
    return name


# Take in a list of filenames and convert applicable names to an expression. 
def inverse_pattern(filenames):
    # make groups of at least 80% similar files
    groups = {}
    for f1 in filenames:
        if f1 not in groups:
            groups[f1] = []
        else:
            continue

        # some heuristics:
        # - for the first implementation we will not attempt file names of different lengths.
        # - If the file names are different lengths we probably don't want to group them unless
        #   the difference is numerical like "file1" and "file10"
        # - Otherwise the files are probably different categorically and it would be confusing to read
        for f2 in filenames:
            if f1 != f2:
                # ignore different lengths for now
                if len(f1) != len(f2):
                    continue

                e_distance = Levenshtein.distance(f1, f2)
                
                # if more than 20% different ignore
                if e_distance > len(f1) // 5:
                    continue

                groups[f1].append(f2)
                groups[f2] = None

    # remove keys that have been grouped elsewhere        
    groups = {k: v for k, v in groups.items() if v != None}

    # add the files who are not described by expression
    file_constants = []

    def get_indexes(ops):
        return [idx[1] for idx in ops]

    expressions = []
    # find the expression for each file group
    for k in groups:
        if len(groups[k]) == 0:
            file_constants.append(k)
            continue
        test_pair = (k, groups[k][0])

        ops = Levenshtein.editops(*test_pair)
        edit_distance = len(ops)
        indexes = get_indexes(ops)
        
        replaced_at_idx = {}
        for idx in indexes:
            replaced_at_idx[idx] = {k[idx]}
            
        test_string = sub_idx(indexes, k)

        non_matches = 0
        for v in groups[k]:
            # get the chars from string v at each index scheduled for replacement
            for idx in indexes:
                replaced_at_idx[idx].update({v[idx]})

            # test the next filename with the same edits. If it doesn't work add to the ops    
            test_v = sub_idx(get_indexes(ops), v)
            if test_string != test_v:
                ops += Levenshtein.editops(test_string, test_v)
                indexes = get_indexes(ops)
                for idx in indexes:
                    replaced_at_idx[idx].update({test_string[idx], test_v[idx]})
                test_string = sub_idx(get_indexes(ops), test_string)
                non_matches += 1
        
        #print("Iterations:", non_matches + 1) # plus initial
        
        chars_added = 0
        for idx, values in replaced_at_idx.items():
            values = sorted(values)
            v = [list(v) for g, v in itertools.groupby(values, lambda x: x.isdigit())]
            
            # the values at this index were sequential integers
            if len(v) == 1:
                test_string = sub_idx([idx+chars_added], test_string, token=f'[{v[0][0]}-{v[0][-1]}]')
                chars_added += len(f'[{v[0][0]}-{v[0][-1]}]') - 1
        
        expressions.append(test_string)

    return file_constants, expressions





        
            