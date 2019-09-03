from .syslog_abstract import AbstractSyslog
from .file_handler import ReadJson, ReadErroJson
from .exception_handling import AVAException, AVASysLogErrorHandling

from antlr4 import *
from parser.syslogLexer import syslogLexer
from parser.syslogParser import syslogParser

import os

from avalogger.core import AvaLogger

confs = {"name": "AVASyslog", "path":
    "/var/log/avapot/AVASyslog.log", "level": "info"}
logger = AvaLogger.register(confs)


class SyslogUbuntu(AbstractSyslog):
    def __init__(self, *args, **kwargs):
        '''
        err_code  here is the module to read and parse json file that we
        create for handle our different situation.

        :param args:
        :param kwargs:
        '''
        self.obj_err = AVASysLogErrorHandling()
        self.err_code = ReadErroJson("error_code.json")
        self.obj_conf = ReadJson('config.json')
    @staticmethod
    def get_conn_type_sign(conn_type):
        conn_type_ = conn_type.lower()
        type_sign = '@@' if conn_type_ == 'tcp' else '@'
        return type_sign

    def add_syslog(self, dns, port, conn_type):
        """
        This method is called by add_syslog from avasyslog_interface,
        and get some parameters (ip, port , conn_type)
        :param dns:
        :param port:
        :param conn_type:
        :return:
        """
        try:
            check = self.obj_err.public_check(dns, port, conn_type)
            if check['result']:
                tree = self.pars_tree()
                type_conn = self.get_conn_type_sign(conn_type)
                contain_str = self.obj_conf.get_contain_str()
                dic = {'conn_type': type_conn, 'port': port, 'dns': dns,
                       'contain': contain_str}
                tree['syslog_list'].append(dic)
                result_file = self.write_output(tree)
                if result_file['result']:
                    result_reset = self.restart_syslog()
                    if result_reset['result']:
                        result = True
                        msg = self.err_code.get_err("200")
                    else:
                        result = False
                        msg = result_reset['msg']
                else:
                    result = False
                    msg = result_file["msg"]
            else:
                result = False
                msg = check['msg']
        except Exception as e:
            AVAException(e)
            msg = self.err_code.get_err("500")
            result = False

        # logger.log(msg['msg'])
        restart_service = self.restart_syslog()
        if not restart_service['result']:
            result = False
            msg = restart_service['msg']
        return {'result': result, 'msg': msg}

    def edit_syslog(self, from_, to_):
        find_row = False
        try:
            check_from = self.obj_err.public_check(from_['dns'], from_['port'],
                                                   from_['conn_type'])

            check_to = self.obj_err.public_check(to_['dns'], to_['port'],
                                                 to_['conn_type'])

            if check_from['result'] and check_to['result']:
                tree = self.pars_tree()
                for syslog in tree['syslog_list']:
                    type_conn = self.get_conn_type_sign(from_["conn_type"])
                    if syslog['dns'] == from_["dns"] and \
                                    syslog['port'] == from_["port"] and \
                                    syslog['conn_type'] == type_conn:
                        find_row = True
                        syslog['dns'] = to_["dns"]
                        syslog['port'] = to_["port"]
                        syslog['conn_type'] = self.get_conn_type_sign(
                            to_["conn_type"])

                if find_row:
                    result_file = self.write_output(tree)
                    if result_file["result"]:
                        result_reset = self.restart_syslog()
                        if result_reset['result']:
                            result = True
                            msg = self.err_code.get_err("200")
                        else:
                            result = False
                            msg = result_reset['msg']
                    else:
                        result = False
                        msg = result_file["msg"]
                else:
                    result = False
                    msg = self.err_code.get_err("512")
            else:
                result = False
                msg = check_from['msg'] if check_from['result'] else \
                    check_to['msg']
        except Exception as e:
            AVAException(e)
            msg = self.err_code.get_err("500")
            result = False

        restart_service = self.restart_syslog()
        if not restart_service['result']:
            result = False
            msg = restart_service['msg']
        logger.log(msg['msg'])
        return {'result': result, 'msg': msg}

    def remove_syslog(self, dns, port, conn_type):
        find_row = False
        try:
            check = self.obj_err.public_check(dns, port, conn_type)
            if check['result']:
                tree = self.pars_tree()
                index = 0
                for syslog in tree['syslog_list']:
                    type_conn = self.get_conn_type_sign(conn_type)
                    if syslog['dns'] == dns and syslog['port'] == \
                            port and syslog['conn_type'] == \
                            type_conn:
                        del tree['syslog_list'][index]
                        find_row = True
                    index = index + 1
                if find_row is True:
                    result_file = self.write_output(tree)
                    if result_file["result"]:
                        result_reset = self.restart_syslog()
                        if result_reset['result']:
                            result = True
                            msg = self.err_code.get_err("200")
                        else:
                            result = False
                            msg = result_reset['msg']
                    else:
                        result = False
                        msg = result_file["msg"]
                else:
                    result = False
                    msg = self.err_code.get_err("511")
            else:
                result = False
                msg = check['msg']
        except Exception as e:
            logger.log('msg, :', 'error')
            AVAException(e)
            msg = self.err_code.get_err("500")
            result = False
        restart_service = self.restart_syslog()
        if not restart_service['result']:
            result = False
            msg = restart_service['msg']
        logger.log(msg['msg'])
        return {'result': result, 'msg': msg}

    def reset_syslog(self):
        main_file = self.obj_conf.get_main_file()
        dest_file = self.obj_conf.get_dest_file1()
        try:
            result = os.system("cp " + main_file + " " + dest_file)
            if result == 0:
                result = self.restart_syslog()
                if result['result']:
                    result = True
                    msg = self.err_code.get_err("200")
                else:
                    result = False
                    msg = result['msg']
            else:
                msg = self.err_code.get_err("500")
                result = False
        except Exception as e:
            AVAException(e)
            msg = self.err_code.get_err("500")
            result = False
        # logger.log(msg['msg'])
        return {'result': result, 'msg': msg}

    def restart_syslog(self):
        try:
            result = os.system("systemctl restart rsyslog")
            if result == 0:
                result = True
                msg = self.err_code.get_err("200")
        except Exception as e:
            AVAException(e)
            msg = self.err_code.get_err("500")
            result = False
        logger.log(msg['msg'])
        return {'result': result, 'msg': msg}

    def active_syslog(self):
        try:
            result = os.system("systemctl start rsyslog")
            if result == 0:
                result = True
                msg = self.err_code.get_err("200")
        except Exception as e:
            AVAException(e)
            msg = self.err_code.get_err("500")
            result = False
        logger.log(msg['msg'])
        return {'result': result, 'msg': msg}

    def inactive_syslog(self):
        try:
            result = os.system("systemctl stop rsyslog")
            if result == 0:
                result = True
                msg = self.err_code.get_err("200")
        except Exception as e:
            AVAException(e)
            msg = self.err_code.get_err("500")
            result = False
        logger.log(msg['msg'])
        return {'result': result, 'msg': msg}

    def write_output(self, result):
        try:
            dest_file = self.obj_conf.get_dest_file1()
            with open(dest_file, "w") as file:
                file.write(result['comment'])
                for syslog in result['syslog_list']:

                    syslog_line = syslog['contain'] + " "+syslog['conn_type'] +syslog[
                        'dns'] + ':' + syslog['port'] + "\n"
                    file.write(syslog_line)


                result = True
                msg = self.err_code.get_err("200")
        except Exception as e:
            AVAException(e)
            msg = self.err_code.get_err("513")
            result = False
        return {'result': result, 'msg': msg}

    def pars_tree(self):
        """
        this method will pars instance of the object_conf in
        5 step with five different method .
        :return:
        """
        # src_file = self.obj_conf.get_src_file()
        dest_file = self.obj_conf.get_dest_file1()
        lexer = syslogLexer(FileStream(dest_file))

        stream = CommonTokenStream(lexer)

        parser = syslogParser(stream)

        tree = parser.listAll()

        result = self.handle_expression(tree)

        return result

    @staticmethod
    def handle_expression(expr):

        syslog_list = []
        for child in expr.getChildren():

            dic_syslog = {}
            # print (child.system())

            if hasattr(child, 'Contain'):
                dic_syslog['contain'] = str(child.Contain())

            if hasattr(child, 'ConnectionType'):
                dic_syslog['conn_type'] = str(child.ConnectionType())

            if hasattr(child, 'DNSID'):
                dic_syslog['dns'] = str(child.DNSID())

            if hasattr(child, 'Port'):
                dic_syslog['port'] = str(child.Port())

            if len(dic_syslog) != 0:
                syslog_list.append(dic_syslog)
        return {'comment': str(expr.Comment()), 'syslog_list': syslog_list}

    def get_all_syslog(self):
        result = []
        tree = self.pars_tree()
        if 'syslog_list' in tree.keys():
            result = tree['syslog_list']
        return result
