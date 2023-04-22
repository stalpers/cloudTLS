# config helper
class ConfigHelper:

    def is_true(self,str):
        return str.lower() in ['true', '1', 't', 'y', 'yes']

    def set_log_level(self, str):
        str=str.upper()
        if str in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            return(str)
        else:
            return("NOTSET")