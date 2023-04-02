def get_powerset(some_list):
    """Returns all subsets of size 0 - len(some_list) for some_list"""
    if len(some_list) == 0:
        return [[]]

    subsets = []
    first_element = some_list[0]
    remaining_list = some_list[1:]
    # Strategy: get all the subsets of remaining_list. For each
    # of those subsets, a full subset list will contain both
    # the original subset as well as a version of the subset
    # that contains first_element
    for partial_subset in get_powerset(remaining_list):
        subsets.append(partial_subset)
        subsets.append(partial_subset[:] + [first_element])

    return subsets

if __name__=="__main__":
    lista=[1,2,3,4]
    C=get_powerset(lista)
    for l in C:
        print(l)
