# Path calss
import copy

class Path(object):
    def __init__(self, pclist = None, load = None, store = None) -> None:
        self.pc_list = pclist or []
        self.load_var_list = load or []
        self.store_var_list = store or []
        self.path_number = 0
        self.unreachable_flag = False

    def __copy__(self):
        new_pc_list = self.pc_list[:]
        new_load_var_list = copy.copy(self.load_var_list)
        new_store_var_list = copy.copy(self.store_var_list)
        new_path = Path(new_pc_list, new_load_var_list, new_store_var_list)
        new_path.path_number = self.path_number
        new_path.unreachable_flag = self.unreachable_flag
        return new_path