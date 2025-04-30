def f_obfs1(a_param):
    if not isinstance(a_param, int) or a_param < 0: raise ValueError("err_neg")
    elif a_param < 2: return 1 # Handles 0 and 1
    else:
        r_val = 1
        for x_iter in range(2, a_param + 1): r_val *= x_iter
        return r_val