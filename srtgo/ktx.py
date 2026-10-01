"""
korail2.korail2
~~~~~~~~~~~~~~~

:copyright: (c) 2014 by Taehoon Kim.
:license: BSD, see LICENSE for more details.
"""

import base64
try:
    import curl_cffi
    HAS_CURL_CFFI = True
except ImportError:
    import requests
    HAS_CURL_CFFI = False
import itertools
import json
import random
import re
import string
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from datetime import datetime, timedelta
from functools import reduce


# Constants
EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")
PHONE_NUMBER_REGEX = re.compile(r"(\d{3})-(\d{3,4})-(\d{4})")

USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 13; SM-S928N Build/UP1A.231005.007)"

DEFAULT_HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "User-Agent": USER_AGENT,
    "Host": "smart.letskorail.com",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}

KORAIL_MOBILE = "https://smart.letskorail.com:443/classes/com.korail.mobile"

DYNAPATH_PATHS = [
    "/classes/com.korail.mobile.certification.TicketReservation",
    "/classes/com.korail.mobile.nonMember.NonMemTicket",
    "/classes/com.korail.mobile.seatMovie.ScheduleView",
    "/classes/com.korail.mobile.seatMovie.ScheduleViewSpecial",
    "/classes/com.korail.mobile.trn.prcFare.do",
    "/classes/com.korail.mobile.login.Login",
]


class DynaPathMasterEngine:
    APP_ID = "com.korail.talk"
    AS_VALUE = "%5B38ff229cb34c7dda8e28220a2d750cce%5D"
    DEVICE_MODEL = "SM-S928N"
    OS_TYPE = "Android"
    SDK_VERSION = "v1"

    def __init__(self):
        self.TABLE = "3FE9jgRD4KdCyuawklqGJYmvfMn15P7US8XbxeLQtWT6OicBAopINs2Vh0HZrz"
        self.I8, self.I9, self.I10 = 161, 30, 2
        self.app_start_ts = str(int(time.time() * 1000))

    def string2xA1s(self, data_str):
        result = []
        i = 0
        while i < len(data_str):
            cp = ord(data_str[i])
            i += 1
            if cp < 128:
                result.append(cp)
            elif cp < 2048:
                result.append(128 | ((cp >> 7) & 15))
                result.append(cp & 127)
            elif cp >= 262144:
                result.append(160)
                result.append((cp >> 14) & 127)
                result.append((cp >> 7) & 127)
                result.append(cp & 127)
            elif (63488 & cp) != 55296:
                result.append(((cp >> 14) & 15) | 144)
                result.append((cp >> 7) & 127)
                result.append(cp & 127)
        return result

    def make_key(self, key_str):
        big_int_add = 0
        for char in key_str:
            cp = ord(char)
            i9_bit = 32768
            for _ in range(16):
                if (i9_bit & cp) != 0:
                    break
                i9_bit >>= 1
            big_int_add = (big_int_add * (i9_bit << 1)) + cp
        return big_int_add

    def _internal_i(self, base_table, remainder, encode_size, current_sb):
        j8_count = 0
        for k in range(len(base_table)):
            char = base_table[k]
            if char not in current_sb:
                if j8_count == remainder:
                    return char
                j8_count += 1
        return " "

    def make_encode_table(self, num, encode_size, base_table):
        sb = ""
        temp_num = num
        for i in range(encode_size):
            j8_divisor = encode_size - i
            remainder = temp_num % j8_divisor
            char = self._internal_i(base_table, remainder, len(base_table), sb)
            sb += char
            temp_num //= j8_divisor
        return sb

    def encode_normal_be(self, data_str, table, i8=161, i9=30, i10=2):
        list_data = self.string2xA1s(data_str)
        sb, i_arr = [], [0] * (i10 + 1)
        idx, size = 0, len(list_data) % i10
        size2 = len(list_data) - size
        while idx < size2:
            val = 0
            for _ in range(i10):
                val = (val * i8) + list_data[idx]
                idx += 1
            for i in range(i10 + 1):
                i_arr[i] = val % i9
                val //= i9
            for i in range(i10, -1, -1):
                sb.append(table[i_arr[i]])
        if size > 0:
            val = 0
            for _ in range(size):
                val = (val * i8) + list_data[idx]
                idx += 1
            for i in range(size + 1):
                i_arr[i] = val % i9
                val //= i9
            while size >= 0:
                sb.append(table[i_arr[size]])
                size -= 1
        return "".join(sb)

    def generate_token(self, device_id, ts, rand):
        plaintext = (
            f"ai={self.APP_ID}&di={device_id}&as={self.AS_VALUE}&"
            f"su=false&dbg=false&emu=false&hk=false&it={self.app_start_ts}&"
            f"ts={ts}&rt=0&os=13&dm={self.DEVICE_MODEL}&st={self.OS_TYPE}&sv={self.SDK_VERSION}"
        )
        dyn_key = f"v1+{rand}+{ts}"
        key_enc = self.encode_normal_be(dyn_key, self.TABLE, self.I8, self.I9, self.I10)
        big_key = self.make_key(dyn_key)
        custom_table = self.make_encode_table(big_key, self.I9, self.TABLE)
        body_enc = self.encode_normal_be(plaintext, custom_table, self.I8, self.I9, self.I10)
        return f"bEeEP{self.TABLE[len(key_enc)]}{key_enc}{body_enc}"
API_ENDPOINTS = {
    "login": f"{KORAIL_MOBILE}.login.Login",
    "logout": f"{KORAIL_MOBILE}.common.logout",
    "search_schedule": f"{KORAIL_MOBILE}.seatMovie.ScheduleView",
    "reserve": f"{KORAIL_MOBILE}.certification.TicketReservation",
    "cancel": f"{KORAIL_MOBILE}.reservationCancel.ReservationCancelChk",
    "myticketseat": f"{KORAIL_MOBILE}.refunds.SelTicketInfo",
    "myticketlist": f"{KORAIL_MOBILE}.myTicket.MyTicketList",
    "myreservationview": f"{KORAIL_MOBILE}.reservation.ReservationView",
    "myreservationlist": f"{KORAIL_MOBILE}.certification.ReservationList",
    "pay": f"{KORAIL_MOBILE}.payment.ReservationPayment",
    "refund": f"{KORAIL_MOBILE}.refunds.RefundsRequest",
    "code": f"{KORAIL_MOBILE}.common.code.do",
}


# Schedule classes
class Schedule:
    """Base class for train schedules"""

    def __init__(self, data):
        self.train_type = data.get("h_trn_clsf_cd")
        self.train_type_name = data.get("h_trn_clsf_nm")
        self.train_group = data.get("h_trn_gp_cd")
        self.train_no = data.get("h_trn_no")
        self.delay_time = data.get("h_expct_dlay_hr")

        self.dep_name = data.get("h_dpt_rs_stn_nm")
        self.dep_code = data.get("h_dpt_rs_stn_cd")
        self.dep_date = data.get("h_dpt_dt")
        self.dep_time = data.get("h_dpt_tm")

        self.arr_name = data.get("h_arv_rs_stn_nm")
        self.arr_code = data.get("h_arv_rs_stn_cd")
        self.arr_date = data.get("h_arv_dt")
        self.arr_time = data.get("h_arv_tm")

        self.run_date = data.get("h_run_dt")

    def __repr__(self):
        dep_time = f"{self.dep_time[:2]}:{self.dep_time[2:4]}"
        arr_time = f"{self.arr_time[:2]}:{self.arr_time[2:4]}"

        dep_date = f"{int(self.dep_date[4:6]):02d}/{int(self.dep_date[6:]):02d}"

        train_line = f"[{self.train_type_name[:3]} {self.train_no}]"

        return (
            f"{train_line:<11s}"
            f"{dep_date} {dep_time}~{arr_time}  "
            f"{self.dep_name}~{self.arr_name}"
        )


class Train(Schedule):
    """Train schedule with seat availability"""

    def __init__(self, data):
        super().__init__(data)
        self.reserve_possible = data.get("h_rsv_psb_flg")
        self.reserve_possible_name = data.get("h_rsv_psb_nm")
        self.special_seat = data.get("h_spe_rsv_cd")
        self.general_seat = data.get("h_gen_rsv_cd")
        self.wait_reserve_flag = data.get("h_wait_rsv_flg")
        if self.wait_reserve_flag:
            self.wait_reserve_flag = int(self.wait_reserve_flag)

    def __repr__(self):
        repr_str = super().__repr__()

        dep_time = f"{self.dep_time[:2]}:{self.dep_time[2:4]}"
        arr_time = f"{self.arr_time[:2]}:{self.arr_time[2:4]}"

        duration = (int(self.arr_time[:2]) * 60 + int(self.arr_time[2:4])) - (
            int(self.dep_time[:2]) * 60 + int(self.dep_time[2:4])
        )

        if duration < 0:
            duration += 24 * 60

        if self.reserve_possible_name:
            repr_str += f"  특실 {'가능' if self.has_special_seat() else '매진'}"
            repr_str += f", 일반실 {'가능' if self.has_general_seat() else '매진'}"
            if self.wait_reserve_flag >= 0:
                repr_str += f", 예약대기 {'가능' if self.has_general_waiting_list() else '매진'}"
        repr_str += f" ({duration:>3d}분)"
        return repr_str

    def has_special_seat(self):
        return self.special_seat == "11"

    def has_general_seat(self):
        return self.general_seat == "11"

    def has_seat(self):
        return self.has_general_seat() or self.has_special_seat()

    def has_waiting_list(self):
        return self.has_general_waiting_list()

    def has_general_waiting_list(self):
        return self.wait_reserve_flag == 9


class Ticket(Train):
    """Train ticket information"""

    def __init__(self, data):
        raw_data = data["ticket_list"][0]["train_info"][0]
        super().__init__(raw_data)
        self.seat_no_end = raw_data.get("h_seat_no_end")
        self.seat_no_count = int(raw_data.get("h_seat_cnt"))
        self.buyer_name = raw_data.get("h_buy_ps_nm")
        self.sale_date = raw_data.get("h_orgtk_sale_dt")
        self.pnr_no = raw_data.get("h_pnr_no")
        self.sale_info1 = raw_data.get("h_orgtk_wct_no")
        self.sale_info2 = raw_data.get("h_orgtk_ret_sale_dt")
        self.sale_info3 = raw_data.get("h_orgtk_sale_sqno")
        self.sale_info4 = raw_data.get("h_orgtk_ret_pwd")
        self.price = int(raw_data.get("h_rcvd_amt"))
        self.car_no = raw_data.get("h_srcar_no")
        self.seat_no = raw_data.get("h_seat_no")

    def __repr__(self):
        repr_str = super(Train, self).__repr__()
        repr_str += f" => {self.car_no}호"
        if int(self.seat_no_count) != 1:
            repr_str += f" {self.seat_no}~{self.seat_no_end}"
        else:
            repr_str += f" {self.seat_no}"
        repr_str += f", {self.price}원"
        return repr_str

    def get_ticket_no(self):
        return "-".join(
            map(
                str,
                (self.sale_info1, self.sale_info2, self.sale_info3, self.sale_info4),
            )
        )


class Reservation(Train):
    """Train reservation information"""

    def __init__(self, data):
        super().__init__(data)
        self.dep_date = data.get("h_run_dt")
        self.arr_date = data.get("h_run_dt")
        self.rsv_id = data.get("h_pnr_no")
        self.seat_no_count = int(data.get("h_tot_seat_cnt"))
        self.buy_limit_date = data.get("h_ntisu_lmt_dt")
        self.buy_limit_time = data.get("h_ntisu_lmt_tm")
        self.price = int(data.get("h_rsv_amt"))
        self.journey_no = data.get("txtJrnySqno", "001")
        self.journey_cnt = data.get("txtJrnyCnt", "01")
        self.rsv_chg_no = data.get("hidRsvChgNo", "00000")
        self.is_waiting = (
            self.buy_limit_date == "00000000" or self.buy_limit_time == "235959"
        )

    def __repr__(self):
        repr_str = super().__repr__()
        repr_str += f", {self.price}원({self.seat_no_count}석)"
        if self.is_waiting:
            repr_str += ", 예약대기"
        else:
            buy_limit_time = f"{self.buy_limit_time[:2]}:{self.buy_limit_time[2:4]}"
            buy_limit_date = (
                f"{int(self.buy_limit_date[4:6])}월 {int(self.buy_limit_date[6:])}일"
            )
            repr_str += f", 구입기한 {buy_limit_date} {buy_limit_time}"
        return repr_str


class Seat:
    """Train seat information"""

    def __init__(self, data: dict):
        self.car = data.get("h_srcar_no")
        self.seat = data.get("h_seat_no")
        self.seat_type = data.get("h_psrm_cl_nm")
        self.passenger_type = data.get("h_psg_tp_dv_nm")
        self.price = int(data.get("h_rcvd_amt", 0))
        self.original_price = int(data.get("h_seat_prc", 0))
        self.discount = int(data.get("h_dcnt_amt", 0))
        self.is_waiting = self.seat == ""

    def __repr__(self):
        if self.is_waiting:
            return (
                f"예약대기 ({self.seat_type}) {self.passenger_type}"
                f"[{self.price}원({self.discount}원 할인)]"
            )
        else:
            return (
                f"{self.car}호차 {self.seat} ({self.seat_type}) {self.passenger_type} "
                f"[{self.price}원({self.discount}원 할인)]"
            )


# Passenger classes
class Passenger:
    """Base class for passengers"""

    def __init_internal__(
        self, typecode, count=1, discount_type="000", card="", card_no="", card_pw=""
    ):
        self.typecode = typecode
        self.count = count
        self.discount_type = discount_type
        self.card = card
        self.card_no = card_no
        self.card_pw = card_pw

    @staticmethod
    def reduce(passenger_list):
        if not all(isinstance(x, Passenger) for x in passenger_list):
            raise TypeError("Passengers must be based on Passenger")
        groups = itertools.groupby(passenger_list, lambda x: x.group_key())
        return list(
            filter(
                lambda x: x.count > 0,
                [reduce(lambda a, b: a + b, g) for k, g in groups],
            )
        )

    def __add__(self, other):
        if not isinstance(other, self.__class__):
            raise TypeError("Cannot add different passenger types")
        if self.group_key() != other.group_key():
            raise TypeError(
                f"Cannot add passengers with different group keys: {self.group_key()} vs {other.group_key()}"
            )
        return self.__class__(
            count=self.count + other.count,
            discount_type=self.discount_type,
            card=self.card,
            card_no=self.card_no,
            card_pw=self.card_pw,
        )

    def group_key(self):
        return f"{self.typecode}_{self.discount_type}_{self.card}_{self.card_no}_{self.card_pw}"

    def get_dict(self, index):
        index = str(index)
        return {
            f"txtPsgTpCd{index}": self.typecode,
            f"txtDiscKndCd{index}": self.discount_type,
            f"txtCompaCnt{index}": self.count,
            f"txtCardCode_{index}": self.card,
            f"txtCardNo_{index}": self.card_no,
            f"txtCardPw_{index}": self.card_pw,
        }


class AdultPassenger(Passenger):
    def __init__(self, count=1, discount_type="000", card="", card_no="", card_pw=""):
        Passenger.__init_internal__(
            self, "1", count, discount_type, card, card_no, card_pw
        )


class ChildPassenger(Passenger):
    def __init__(self, count=1, discount_type="000", card="", card_no="", card_pw=""):
        Passenger.__init_internal__(
            self, "3", count, discount_type, card, card_no, card_pw
        )


class ToddlerPassenger(Passenger):
    def __init__(self, count=1, discount_type="321", card="", card_no="", card_pw=""):
        Passenger.__init_internal__(
            self, "3", count, discount_type, card, card_no, card_pw
        )


class SeniorPassenger(Passenger):
    def __init__(self, count=1, discount_type="131", card="", card_no="", card_pw=""):
        Passenger.__init_internal__(
            self, "1", count, discount_type, card, card_no, card_pw
        )


class Disability1To3Passenger(Passenger):
    def __init__(self, count=1, discount_type="111", card="", card_no="", card_pw=""):
        Passenger.__init_internal__(
            self, "1", count, discount_type, card, card_no, card_pw
        )


class Disability4To6Passenger(Passenger):
    def __init__(self, count=1, discount_type="112", card="", card_no="", card_pw=""):
        Passenger.__init_internal__(
            self, "1", count, discount_type, card, card_no, card_pw
        )


# Options
class TrainType:
    KTX = "100"
    SAEMAEUL = "101"
    MUGUNGHWA = "102"
    TONGGUEN = "103"
    NURIRO = "102"
    ALL = "109"
    AIRPORT = "105"
    KTX_SANCHEON = "100"
    ITX_SAEMAEUL = "101"
    ITX_CHEONGCHUN = "104"


class ReserveOption:
    GENERAL_FIRST = "GENERAL_FIRST"
    GENERAL_ONLY = "GENERAL_ONLY"
    SPECIAL_FIRST = "SPECIAL_FIRST"
    SPECIAL_ONLY = "SPECIAL_ONLY"


# Korail errors
class KorailError(Exception):
    """Base class for Korail errors"""

    def __init__(self, msg, code=None):
        self.msg = msg
        self.code = code

    def __str__(self):
        return f"{self.msg} ({self.code})"


class NeedToLoginError(KorailError):
    codes = {"P058"}

    def __init__(self, code=None):
        super().__init__("Need to Login", code)


class NoResultsError(KorailError):
    codes = {"P100", "WRG000000", "WRD000061", "WRT300005"}

    def __init__(self, code=None):
        super().__init__("No Results", code)


class SoldOutError(KorailError):
    codes = {"IRT010110", "ERR211161"}

    def __init__(self, code=None):
        super().__init__("Sold out", code)


class NetFunnelError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


# NetFunnel
class NetFunnelHelper:
    NETFUNNEL_URL = "http://nf.letskorail.com/ts.wseq"

    WAIT_STATUS_PASS = "200"
    WAIT_STATUS_FAIL = "201"
    ALREADY_COMPLETED = "502"

    OP_CODE = {
        "getTidchkEnter": "5101",
        "chkEnter": "5002",
        "setComplete": "5004",
    }

    DEFAULT_HEADERS = {
        "Host": "nf.letskorail.com",
        "Connection": "Keep-Alive",
        "User-Agent": "Apache-HttpClient/UNAVAILABLE (java 1.4)",
    }

    def __init__(self):
        if HAS_CURL_CFFI:
            self._session = curl_cffi.Session(impersonate="chrome131_android")
        else:
            self._session = requests.session()
        self._session.headers.update(self.DEFAULT_HEADERS)
        self._cached_key = None
        self._last_fetch_time = 0
        self._cache_ttl = 50  # 50 seconds

    def run(self):
        current_time = time.time()
        if self._is_cache_valid(current_time):
            return self._cached_key

        try:
            status, self._cached_key, nwait = self._start()
            self._last_fetch_time = current_time

            while status == self.WAIT_STATUS_FAIL:
                print(f"\r현재 {nwait}명 대기중...", end="", flush=True)
                time.sleep(1)
                status, self._cached_key, nwait = self._check()

            # Try completing once
            status, _, _ = self._complete()
            if status == self.WAIT_STATUS_PASS or status == self.ALREADY_COMPLETED:
                return self._cached_key

            self.clear()
            raise NetFunnelError("Failed to complete NetFunnel")

        except Exception as ex:
            self.clear()
            raise NetFunnelError(str(ex))

    def clear(self):
        self._cached_key = None
        self._last_fetch_time = 0

    def _start(self):
        return self._make_request("getTidchkEnter")

    def _check(self):
        return self._make_request("chkEnter")

    def _complete(self):
        return self._make_request("setComplete")

    def _make_request(self, opcode: str):
        params = self._build_params(self.OP_CODE[opcode])
        response = self._parse(
            self._session.get(self.NETFUNNEL_URL, params=params).text
        )
        return response.get("status"), response.get("key"), response.get("nwait")

    def _build_params(self, opcode: str, key: str = None) -> dict:
        params = {"opcode": opcode}

        if opcode in (self.OP_CODE["getTidchkEnter"], self.OP_CODE["chkEnter"]):
            params.update({"sid": "service_1", "aid": "act_8"})
            if opcode == self.OP_CODE["chkEnter"]:
                params.update({"key": key or self._cached_key, "ttl": "1"})
        elif opcode == self.OP_CODE["setComplete"]:
            params["key"] = key or self._cached_key

        return params

    def _parse(self, response: str) -> dict:
        status, params_str = response.split(":", 1)
        if not params_str:
            raise NetFunnelError("Failed to parse NetFunnel response")

        params = dict(
            param.split("=", 1) for param in params_str.split("&") if "=" in param
        )
        params["status"] = status
        return params

    def _is_cache_valid(self, current_time: float) -> bool:
        return bool(
            self._cached_key
            and (current_time - self._last_fetch_time) < self._cache_ttl
        )


class Korail:
    """Main Korail API interface"""

    _sid_key = b"2485dd54d9deaa36"
    _device_id = "558a4f02041657ea"

    def __init__(self, korail_id, korail_pw, auto_login=True, verbose=False):
        if HAS_CURL_CFFI:
            self._session = curl_cffi.Session()
        else:
            self._session = requests.session()
        self._session.headers.update(DEFAULT_HEADERS)
        self._netfunnel = NetFunnelHelper()
        self._engine = DynaPathMasterEngine()
        self._device = "AD"
        self._version = "250601002"
        self._key = "korail1234567890"
        self._idx = None
        self.korail_id = korail_id
        self.korail_pw = korail_pw
        self.verbose = verbose
        self.logined = False
        self.membership_number = None
        self.name = None
        self.email = None
        self.phone_number = None
        if auto_login:
            self.login(korail_id, korail_pw)

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"[*] {msg}")

    def _generate_sid(self, ts):
        plaintext = (f"{self._device}{ts}").encode("utf-8")
        cipher = AES.new(self._sid_key, AES.MODE_CBC, iv=self._sid_key)
        return base64.b64encode(cipher.encrypt(pad(plaintext, 16))).decode("utf-8") + "\n"

    def _get_auth_headers_and_sid(self, url):
        headers = {}
        sid = None
        if any(path in url for path in DYNAPATH_PATHS):
            ts = int(time.time() * 1000)
            rand = "".join(random.choices(string.ascii_uppercase + string.digits, k=4))
            token = self._engine.generate_token(self._device_id, ts, rand)
            headers["x-dynapath-m-token"] = token
            sid = self._generate_sid(ts)
        return headers, sid

    def __enc_password(self, password):
        url = API_ENDPOINTS["code"]
        data = {"code": "app.login.cphd"}
        r = self._session.post(url, data=data)
        j = json.loads(r.text)

        if j["strResult"] == "SUCC" and j.get("app.login.cphd"):
            self._idx = j["app.login.cphd"]["idx"]
            key = j["app.login.cphd"]["key"]
            encrypt_key = key.encode("utf-8")
            iv = key[:16].encode("utf-8")
            cipher = AES.new(encrypt_key, AES.MODE_CBC, iv)
            padded_data = pad(password.encode("utf-8"), AES.block_size)
            return base64.b64encode(
                base64.b64encode(cipher.encrypt(padded_data))
            ).decode("utf-8")
        return False

    def login(self, korail_id=None, korail_pw=None):
        if korail_id:
            self.korail_id = korail_id
        if korail_pw:
            self.korail_pw = korail_pw

        txt_input_flg = (
            "5"
            if EMAIL_REGEX.match(self.korail_id)
            else "4"
            if PHONE_NUMBER_REGEX.match(self.korail_id)
            else "2"
        )

        url = API_ENDPOINTS["login"]
        headers, sid = self._get_auth_headers_and_sid(url)

        data = {
            "Device": self._device,
            "Version": self._version,
            "txtMemberNo": self.korail_id,
            "txtPwd": self.__enc_password(self.korail_pw),
            "txtInputFlg": txt_input_flg,
            "idx": self._idx,
        }
        if sid:
            data["Sid"] = sid

        r = self._session.post(url, data=data, headers=headers)
        self._log(r.text)
        j = json.loads(r.text)

        if j["strResult"] == "SUCC" and j.get("strMbCrdNo"):
            # self._key = j['Key']
            self.membership_number = j["strMbCrdNo"]
            self.name = j["strCustNm"]
            self.email = j["strEmailAdr"]
            self.phone_number = j["strCpNo"]
            print(
                f"로그인 성공: {self.name} (멤버십번호: {self.membership_number}, 전화번호: {self.phone_number})"
            )
            self.logined = True
            return True
        self.logined = False
        return False

    def logout(self):
        r = self._session.get(API_ENDPOINTS["logout"])
        self._log(r.text)
        self.logined = False

    def _result_check(self, j):
        if j.get("strResult") == "FAIL":
            h_msg_cd = j.get("h_msg_cd")
            h_msg_txt = j.get("h_msg_txt")
            for error in (NoResultsError, NeedToLoginError, SoldOutError):
                if h_msg_cd in error.codes:
                    raise error(h_msg_cd)
            raise KorailError(h_msg_txt, h_msg_cd)
        return True

    def search_train(
        self,
        dep,
        arr,
        date=None,
        time=None,
        train_type=TrainType.ALL,
        passengers=None,
        include_no_seats=False,
        include_waiting_list=False,
    ):
        kst_now = datetime.now() + timedelta(hours=9)
        date = date or kst_now.strftime("%Y%m%d")
        time = time or kst_now.strftime("%H%M%S")
        passengers = passengers or [AdultPassenger()]
        passengers = Passenger.reduce(passengers)

        counts = {
            "adult": sum(p.count for p in passengers if isinstance(p, AdultPassenger)),
            "child": sum(p.count for p in passengers if isinstance(p, ChildPassenger)),
            "toddler": sum(
                p.count for p in passengers if isinstance(p, ToddlerPassenger)
            ),
            "senior": sum(
                p.count for p in passengers if isinstance(p, SeniorPassenger)
            ),
            "disability1to3": sum(
                p.count for p in passengers if isinstance(p, Disability1To3Passenger)
            ),
            "disability4to6": sum(
                p.count for p in passengers if isinstance(p, Disability4To6Passenger)
            ),
        }

        url = API_ENDPOINTS["search_schedule"]
        headers, sid = self._get_auth_headers_and_sid(url)

        data = {
            "Device": self._device,
            "Version": self._version,
            "txtMenuId": "11",
            "radJobId": "1",
            "selGoTrain": train_type,
            "txtTrnGpCd": train_type,
            "txtGoStart": dep,
            "txtGoEnd": arr,
            "txtGoAbrdDt": date,
            "txtGoHour": time,
            "txtPsgFlg_1": counts["adult"],
            "txtPsgFlg_2": counts["child"] + counts["toddler"],
            "txtPsgFlg_3": counts["senior"],
            "txtPsgFlg_4": counts["disability1to3"],
            "txtPsgFlg_5": counts["disability4to6"],
            "txtSeatAttCd_2": "000",
            "txtSeatAttCd_3": "000",
            "txtSeatAttCd_4": "015",
            "ebizCrossCheck": "N",
            "srtCheckYn": "N",  # SRT 함께 보기
            "rtYn": "N",  # 왕복
            "adjStnScdlOfrFlg": "N",  # 인접역 보기
            "mbCrdNo": self.membership_number,
        }

        r = self._session.post(url, params=data, headers=headers)
        self._log(r.text)
        j = json.loads(r.text)

        if self._result_check(j):
            trains = [
                Train(info) for info in j.get("trn_infos", {}).get("trn_info", [])
            ]
            filter_fns = [lambda x: x.has_seat()]

            if include_no_seats:
                filter_fns.append(lambda x: not x.has_seat())
            if include_waiting_list:
                filter_fns.append(lambda x: x.has_waiting_list())

            trains = [t for t in trains if any(f(t) for f in filter_fns)]

            if not trains:
                raise NoResultsError()

            return trains

    def reserve(self, train, passengers=None, option=ReserveOption.GENERAL_FIRST):
        url = API_ENDPOINTS["reserve"]
        headers, sid = self._get_auth_headers_and_sid(url)
        reserving_seat = train.has_seat() or train.wait_reserve_flag < 0
        if reserving_seat:
            is_special_seat = {
                ReserveOption.GENERAL_ONLY: False,
                ReserveOption.SPECIAL_ONLY: True,
                ReserveOption.GENERAL_FIRST: not train.has_general_seat(),
                ReserveOption.SPECIAL_FIRST: train.has_special_seat(),
            }[option]
        else:
            is_special_seat = {
                ReserveOption.GENERAL_ONLY: False,
                ReserveOption.SPECIAL_ONLY: True,
                ReserveOption.GENERAL_FIRST: False,
                ReserveOption.SPECIAL_FIRST: True,
            }[option]

        passengers = passengers or [AdultPassenger()]
        passengers = Passenger.reduce(passengers)
        cnt = sum(p.count for p in passengers)

        data = {
            "Device": self._device,
            "Version": self._version,
            "Key": self._key,
            "txtMenuId": "11",
            "txtJobId": "1101" if reserving_seat else "1102",
            "txtGdNo": "",
            "hidFreeFlg": "N",
            "txtTotPsgCnt": cnt,
            "txtSeatAttCd1": "000",
            "txtSeatAttCd2": "000",
            "txtSeatAttCd3": "000",
            "txtSeatAttCd4": "015",
            "txtSeatAttCd5": "000",
            "txtStndFlg": "N",
            "txtSrcarCnt": "0",
            "txtJrnyCnt": "1",
            "txtJrnySqno1": "001",
            "txtJrnyTpCd1": "11",
            "txtDptDt1": train.dep_date,
            "txtDptRsStnCd1": train.dep_code,
            "txtDptTm1": train.dep_time,
            "txtArvRsStnCd1": train.arr_code,
            "txtTrnNo1": train.train_no,
            "txtRunDt1": train.run_date,
            "txtTrnClsfCd1": train.train_type,
            "txtTrnGpCd1": train.train_group,
            "txtPsrmClCd1": "2" if is_special_seat else "1",
            "txtChgFlg1": "",
            "txtJrnySqno2": "",
            "txtJrnyTpCd2": "",
            "txtDptDt2": "",
            "txtDptRsStnCd2": "",
            "txtDptTm2": "",
            "txtArvRsStnCd2": "",
            "txtTrnNo2": "",
            "txtRunDt2": "",
            "txtTrnClsfCd2": "",
            "txtPsrmClCd2": "",
            "txtChgFlg2": "",
        }

        for i, psg in enumerate(passengers, 1):
            data.update(psg.get_dict(i))

        r = self._session.get(url, params=data, headers=headers)
        self._log(r.text)
        j = json.loads(r.text)
        if self._result_check(j):
            rsv_id = j.get("h_pnr_no")
            reservation = self.reservations(rsv_id)
            return reservation
        else:
            raise SoldOutError()

    def tickets(self):
        data = {
            "Device": self._device,
            "Version": self._version,
            "Key": self._key,
            "txtDeviceId": "",
            "txtIndex": "1",
            "h_page_no": "1",
            "h_abrd_dt_from": "",
            "h_abrd_dt_to": "",
            "hiduserYn": "Y",
        }

        r = self._session.get(API_ENDPOINTS["myticketlist"], params=data)
        self._log(r.text)
        j = json.loads(r.text)
        try:
            if self._result_check(j):
                tickets = []
                for info in j.get("reservation_list", []):
                    ticket = Ticket(info)
                    data = {
                        "Device": self._device,
                        "Version": self._version,
                        "Key": self._key,
                        "h_orgtk_wct_no": ticket.sale_info1,
                        "h_orgtk_ret_sale_dt": ticket.sale_info2,
                        "h_orgtk_sale_sqno": ticket.sale_info3,
                        "h_orgtk_ret_pwd": ticket.sale_info4,
                    }
                    r = self._session.get(API_ENDPOINTS["myticketseat"], params=data)
                    j = json.loads(r.text)
                    if self._result_check(j):
                        seat = (
                            j.get("ticket_infos", {})
                            .get("ticket_info", [{}])[0]
                            .get("tk_seat_info", [{}])[0]
                        )
                        ticket.seat_no = seat.get("h_seat_no")
                        ticket.seat_no_end = None
                    tickets.append(ticket)
                return tickets
        except NoResultsError:
            return []

    def reservations(self, rsv_id=None):
        data = {
            "Device": self._device,
            "Version": self._version,
            "Key": self._key,
        }
        r = self._session.get(API_ENDPOINTS["myreservationview"], params=data)
        self._log(r.text)
        j = json.loads(r.text)
        try:
            if not self._result_check(j):
                return []

            jrny_info = j.get("jrny_infos", {}).get("jrny_info", [])
            reserves = []

            for info in jrny_info:
                train_info = info.get("train_infos", {}).get("train_info", [])
                for tinfo in train_info:
                    reservation = Reservation(tinfo)
                    reservation.tickets, reservation.wct_no = self.ticket_info(
                        reservation.rsv_id
                    )
                    if rsv_id and reservation.rsv_id == rsv_id:
                        return reservation
                    reserves.append(reservation)
            return reserves

        except NoResultsError:
            return []

    def ticket_info(self, rsv_id=None):
        data = {
            "Device": self._device,
            "Version": self._version,
            "Key": self._key,
            "hidPnrNo": rsv_id,
        }
        r = self._session.get(API_ENDPOINTS["myreservationlist"], params=data)
        self._log(r.text)
        j = json.loads(r.text)
        try:
            if not self._result_check(j):
                return []

            wct_no = j.get("h_wct_no")
            if jrny_info := j.get("jrny_infos", {}).get("jrny_info", []):
                if seat_info := jrny_info[0].get("seat_infos", {}).get("seat_info", []):
                    return [Seat(seat) for seat in seat_info], wct_no

        except NoResultsError:
            return None

    def pay_with_card(
        self,
        rsv,
        card_number,
        card_password,
        birthday,
        card_expire,
        installment=0,
        card_type="J",
    ):
        if not isinstance(rsv, Reservation):
            raise TypeError("rsv must be a Reservation instance")

        data = {
            "Device": self._device,
            "Version": self._version,
            "Key": self._key,
            "hidPnrNo": rsv.rsv_id,
            "hidWctNo": rsv.wct_no,
            "hidTmpJobSqno1": "000000",
            "hidTmpJobSqno2": "000000",
            "hidRsvChgNo": "000",
            "hidInrecmnsGridcnt": "1",
            "hidStlMnsSqno1": "1",
            "hidStlMnsCd1": "02",
            "hidMnsStlAmt1": str(rsv.price),
            "hidCrdInpWayCd1": "@",
            "hidStlCrCrdNo1": card_number,
            "hidVanPwd1": card_password,
            "hidCrdVlidTrm1": card_expire,
            "hidIsmtMnthNum1": installment,
            "hidAthnDvCd1": card_type,
            "hidAthnVal1": birthday,
            "hiduserYn": "Y",
        }

        r = self._session.post(API_ENDPOINTS["pay"], data=data)
        self._log(r.text)
        j = json.loads(r.text)
        if self._result_check(j):
            return True
        return False

    def cancel(self, rsv):
        if not isinstance(rsv, Reservation):
            raise TypeError("rsv must be a Reservation instance")
        data = {
            "Device": self._device,
            "Version": self._version,
            "Key": self._key,
            "txtPnrNo": rsv.rsv_id,
            "txtJrnySqno": rsv.journey_no,
            "txtJrnyCnt": rsv.journey_cnt,
            "hidRsvChgNo": rsv.rsv_chg_no,
        }
        r = self._session.post(API_ENDPOINTS["cancel"], data=data)
        self._log(r.text)
        j = json.loads(r.text)
        return self._result_check(j)

    def refund(self, ticket):
        data = {
            "Device": self._device,
            "Version": self._version,
            "Key": self._key,
            "txtPrnNo": ticket.pnr_no,
            "h_orgtk_sale_dt": ticket.sale_info2,
            "h_orgtk_sale_wct_no": ticket.sale_info1,
            "h_orgtk_sale_sqno": ticket.sale_info3,
            "h_orgtk_ret_pwd": ticket.sale_info4,
            "h_mlg_stl": "N",
            "tk_ret_tms_dv_cd": "21",
            "trnNo": ticket.train_no,
            "pbpAcepTgtFlg": "N",
            "latitude": "",
            "longitude": "",
        }
        r = self._session.post(API_ENDPOINTS["refund"], data=data)
        self._log(r.text)
        j = json.loads(r.text)
        return self._result_check(j)

    def clear(self):
        self._log("Clearing the netfunnel key")
        self._netfunnel.clear()

# === KORAIL_MOBILE_API_COMPAT_PATCH_20261001 ===
from korail_mobile_api import (
    KorailClient as _KMAClient,
    TrainSearchQuery as _KMATrainSearchQuery,
    KorailPassengerCounts as _KMAPassengerCounts,
    KorailSeatClass as _KMASeatClass,
)
from korail_mobile_api.mutation_models import CardPayment as _KMACardPayment

try:
    from korail_mobile_api import KorailSeatUnavailableError as _KMASeatUnavailableError
except Exception:
    _KMASeatUnavailableError = ()

try:
    from korail_mobile_api import KorailReservationRefusedError as _KMAReservationRefusedError
except Exception:
    _KMAReservationRefusedError = ()


def _kma_int(value, default=0):
    try:
        if value is None or value == "":
            return default
        return int(value)
    except Exception:
        return default


def _kma_yes(value):
    if value is None:
        return False
    text = str(value).strip().upper()
    return text in {"Y", "1", "YES", "TRUE", "11", "가능", "예약가능"}


def _kma_train_to_legacy(summary):
    general_ok = (
        _kma_yes(getattr(summary, "general_reservation_flag", None))
        or str(getattr(summary, "general_reservation_code", "") or "") == "11"
        or _kma_int(getattr(summary, "standard_remaining_seat_count", 0)) > 0
        or "가능" in str(getattr(summary, "general_availability_name", "") or "")
    )
    special_ok = (
        _kma_yes(getattr(summary, "special_reservation_flag", None))
        or str(getattr(summary, "special_reservation_code", "") or "") == "11"
        or _kma_int(getattr(summary, "first_class_remaining_seat_count", 0)) > 0
        or "가능" in str(getattr(summary, "special_availability_name", "") or "")
    )
    wait_ok = _kma_yes(getattr(summary, "wait_reservation_flag", None))

    data = {
        "h_trn_clsf_cd": getattr(summary, "train_class_code", None) or "100",
        "h_trn_clsf_nm": getattr(summary, "train_class_name", None) or "KTX",
        "h_trn_gp_cd": getattr(summary, "train_group_code", None) or "100",
        "h_trn_no": getattr(summary, "train_no", None) or "",
        "h_expct_dlay_hr": "000000",
        "h_dpt_rs_stn_nm": getattr(summary, "departure_station_name", None) or getattr(summary, "departure_station_code", None) or "",
        "h_dpt_rs_stn_cd": getattr(summary, "departure_station_code", None) or "",
        "h_dpt_dt": getattr(summary, "departure_date", None) or getattr(summary, "run_date", None) or "",
        "h_dpt_tm": getattr(summary, "departure_time", None) or "",
        "h_arv_rs_stn_nm": getattr(summary, "arrival_station_name", None) or getattr(summary, "arrival_station_code", None) or "",
        "h_arv_rs_stn_cd": getattr(summary, "arrival_station_code", None) or "",
        "h_arv_dt": getattr(summary, "arrival_date", None) or getattr(summary, "departure_date", None) or getattr(summary, "run_date", None) or "",
        "h_arv_tm": getattr(summary, "arrival_time", None) or "",
        "h_run_dt": getattr(summary, "run_date", None) or getattr(summary, "departure_date", None) or "",
        "h_rsv_psb_flg": "Y" if (general_ok or special_ok) else "N",
        "h_rsv_psb_nm": "예약가능" if (general_ok or special_ok) else "매진",
        "h_spe_rsv_cd": "11" if special_ok else "00",
        "h_gen_rsv_cd": "11" if general_ok else "00",
        "h_wait_rsv_flg": "9" if wait_ok else "0",
    }
    train = Train(data)
    train._kma_train = summary
    return train


def _kma_passengers(passengers):
    passengers = passengers or [AdultPassenger()]
    passengers = Passenger.reduce(passengers)
    counts = dict(adult=0, teenager=0, child=0, infant=0, senior=0, severe_disability=0, mild_disability=0, guide_dog=0)
    for p in passengers:
        if isinstance(p, ToddlerPassenger):
            counts["infant"] += p.count
        elif isinstance(p, ChildPassenger):
            counts["child"] += p.count
        elif isinstance(p, SeniorPassenger):
            counts["senior"] += p.count
        elif isinstance(p, Disability1To3Passenger):
            counts["severe_disability"] += p.count
        elif isinstance(p, Disability4To6Passenger):
            counts["mild_disability"] += p.count
        elif isinstance(p, AdultPassenger):
            counts["adult"] += p.count
    if sum(counts.values()) == 0:
        counts["adult"] = 1
    return _KMAPassengerCounts(**counts)


class _KMAReservationCompat:
    def __init__(self, hold, train=None):
        self._hold = hold
        self._train = train
        self.rsv_id = getattr(hold, "pnr_no", None)
        self.pnr_no = self.rsv_id
        self.price = _kma_int(getattr(hold, "received_amount", None) or getattr(hold, "total_price", None) or getattr(hold, "total_fare", None), 0)
        self.buy_limit_date = getattr(hold, "payment_deadline_date", None) or ""
        self.buy_limit_time = getattr(hold, "payment_deadline_time", None) or ""
        self.is_waiting = not bool(getattr(hold, "payable", True))
        self.tickets = []
        self.paid = False
        self.is_ticket = False
    def __repr__(self):
        parts = []
        if self._train is not None:
            parts.append(repr(self._train))
        if self.rsv_id:
            parts.append(f"예약번호 {self.rsv_id}")
        if self.price:
            parts.append(f"{self.price:,}원")
        if self.buy_limit_date or self.buy_limit_time:
            parts.append(f"결제기한 {self.buy_limit_date} {self.buy_limit_time}".strip())
        if self.is_waiting:
            parts.append("예약대기")
        return ", ".join(parts) if parts else "KTX 예약"


class _KMAHistoryCompat:
    def __init__(self, pnr_no, text, paid=False):
        self.rsv_id = pnr_no
        self.pnr_no = pnr_no
        self.paid = paid
        self.is_ticket = paid
        self.is_waiting = False
        self.tickets = []
        self._text = text
    def __repr__(self):
        return self._text or (f"예약번호 {self.pnr_no}" if self.pnr_no else "KTX 예약/승차권")


class Korail:
    def __init__(self, korail_id, korail_pw, auto_login=True, verbose=False):
        self.korail_id = korail_id
        self.korail_pw = korail_pw
        self.verbose = verbose
        self.logined = False
        self.membership_number = None
        self.name = None
        self.email = None
        self.phone_number = None
        self._client = _KMAClient()
        if auto_login:
            self.login(korail_id, korail_pw)

    def login(self, korail_id=None, korail_pw=None):
        if korail_id:
            self.korail_id = korail_id
        if korail_pw:
            self.korail_pw = korail_pw
        try:
            session = self._client.login(self.korail_id, self.korail_pw)
            self.logined = True
            self.membership_number = getattr(session, "member_no", None) or getattr(session, "customer_no", None) or self.korail_id
            self.name = getattr(session, "customer_name", None) or getattr(session, "name", None)
            self.phone_number = getattr(session, "phone_no", None) or getattr(session, "phone_number", None)
            self.email = getattr(session, "email", None)
            print(f"로그인 성공: {self.name or '회원'}")
            return True
        except Exception as exc:
            self.logined = False
            raise KorailError(str(exc))

    def logout(self):
        try:
            self._client.logout()
        finally:
            self.logined = False

    def clear(self):
        try:
            self._client.clear_session()
        except Exception:
            pass

    def search_train(self, dep, arr, date=None, time=None, train_type=TrainType.ALL, passengers=None, include_no_seats=False, include_waiting_list=False):
        now = datetime.now()
        date = date or now.strftime("%Y%m%d")
        time = time or now.strftime("%H%M%S")
        pcounts = _kma_passengers(passengers)
        query = _KMATrainSearchQuery(
            departure_station_code=dep,
            arrival_station_code=arr,
            departure_date=date,
            departure_time=time,
            passengers=pcounts.total,
            train_group_code=(train_type or "100"),
            include_srt=False,
            child_passengers=pcounts.child,
            senior_passengers=pcounts.senior,
            high_disability_passengers=pcounts.severe_disability,
            low_disability_passengers=pcounts.mild_disability,
            teenager_passengers=pcounts.teenager,
            infant_passengers=pcounts.infant,
            guide_dog_passengers=pcounts.guide_dog,
        )
        try:
            result = self._client.search_trains(query)
        except Exception as exc:
            msg = str(exc)
            if any(code in msg for code in ("P100", "WRG000000", "WRD000061", "WRT300005")):
                raise NoResultsError()
            raise KorailError(msg)
        trains = [_kma_train_to_legacy(t) for t in result.trains]
        trains = [
            t for t in trains
            if t.has_seat() or (include_waiting_list and t.has_waiting_list()) or include_no_seats
        ]
        if not trains:
            raise NoResultsError()
        return trains

    def reserve(self, train, passengers=None, option=ReserveOption.GENERAL_FIRST):
        summary = getattr(train, "_kma_train", None)
        if summary is None:
            raise KorailError("열차를 새 API로 다시 조회해 주세요.")
        counts = _kma_passengers(passengers)
        general_ok = train.has_general_seat()
        special_ok = train.has_special_seat()
        if option == ReserveOption.GENERAL_ONLY:
            if not general_ok: raise SoldOutError()
            seat_class = _KMASeatClass.GENERAL
        elif option == ReserveOption.SPECIAL_ONLY:
            if not special_ok: raise SoldOutError()
            seat_class = _KMASeatClass.SPECIAL
        elif option == ReserveOption.SPECIAL_FIRST:
            if special_ok: seat_class = _KMASeatClass.SPECIAL
            elif general_ok: seat_class = _KMASeatClass.GENERAL
            else: raise SoldOutError()
        else:
            if general_ok: seat_class = _KMASeatClass.GENERAL
            elif special_ok: seat_class = _KMASeatClass.SPECIAL
            else: raise SoldOutError()
        try:
            hold = self._client.reserve(summary, passengers=counts, seat_class=seat_class)
        except Exception as exc:
            if (_KMASeatUnavailableError and isinstance(exc, _KMASeatUnavailableError)) or (_KMAReservationRefusedError and isinstance(exc, _KMAReservationRefusedError)):
                raise SoldOutError()
            msg = str(exc)
            if any(word in msg.lower() for word in ("sold", "seat", "매진", "잔여")):
                raise SoldOutError()
            raise KorailError(msg)
        if getattr(hold, "str_result", None) not in (None, "SUCC"):
            raise KorailError(getattr(hold, "h_msg_txt", None) or "예약 실패", getattr(hold, "h_msg_cd", None))
        if not getattr(hold, "pnr_no", None):
            raise KorailError("예약 응답에 PNR이 없습니다.")
        return _KMAReservationCompat(hold, train)

    def pay_with_card(self, reservation, card_number, card_password, birthday, expire, installment=0, card_type="J"):
        hold = getattr(reservation, "_hold", None)
        if hold is None:
            pnr_no = getattr(reservation, "pnr_no", None) or getattr(reservation, "rsv_id", None)
            if not pnr_no:
                raise KorailError("결제할 예약번호를 찾을 수 없습니다.")
            hold = self._client.get_reservation_hold(pnr_no)
        try:
            card = _KMACardPayment(
                card_number=str(card_number),
                card_password=str(card_password),
                card_expire=str(expire),
                birthday=str(birthday),
                installment=str(installment),
                card_type=card_type,
            )
            result = self._client.pay_with_card(hold, card)
        except Exception as exc:
            raise KorailError(str(exc))
        ok = getattr(result, "str_result", None) == "SUCC"
        if ok:
            reservation.paid = True
        return ok

    def reservations(self, rsv_id=None):
        try:
            hist = self._client.get_reservation_history()
        except Exception as exc:
            raise KorailError(str(exc))
        out = []
        for journey in getattr(hist, "journeys", ()) or ():
            r = getattr(journey, "reservation", None)
            if r is None:
                continue
            pnr = getattr(r, "pnr_no", None)
            if rsv_id and pnr != rsv_id:
                continue
            trains = getattr(journey, "trains", ()) or ()
            t = trains[0] if trains else None
            if t is not None:
                text = f"[{getattr(t,'train_class_name',None) or 'KTX'} {getattr(t,'train_no',None) or ''}] {getattr(t,'departure_station_name',None) or getattr(t,'departure_station_code',None) or ''}~{getattr(t,'arrival_station_name',None) or getattr(t,'arrival_station_code',None) or ''} {getattr(t,'departure_date',None) or ''} {getattr(t,'departure_time',None) or ''}"
            else:
                text = f"KTX 예약 {pnr or ''}"
            amount = getattr(r, "total_received_amount", None) or getattr(r, "total_price", None)
            if amount: text += f", {amount}원"
            if pnr: text += f", 예약번호 {pnr}"
            paid = str(getattr(r, "payment_flag", "") or "").upper() in {"Y", "1"}
            out.append(_KMAHistoryCompat(pnr, text, paid=paid))
        return out

    def tickets(self):
        try:
            resp = self._client.get_ticket_list()
        except Exception as exc:
            raise KorailError(str(exc))
        out = []
        for reservation in getattr(resp, "reservations", ()) or ():
            for ticket in getattr(reservation, "tickets", ()) or ():
                trains = getattr(ticket, "trains", ()) or ()
                t = trains[0] if trains else None
                pnr = getattr(ticket, "pnr_no", None)
                if t is not None:
                    text = f"[{getattr(t,'train_class_name',None) or 'KTX'} {getattr(t,'train_no',None) or ''}] {getattr(t,'departure_station_name',None) or ''}~{getattr(t,'arrival_station_name',None) or ''} {getattr(t,'departure_date',None) or ''} {getattr(t,'departure_time',None) or ''}"
                else:
                    text = f"KTX 승차권 {pnr or ''}"
                if pnr: text += f", 예약번호 {pnr}"
                out.append(_KMAHistoryCompat(pnr, text, paid=True))
        return out

    def cancel(self, reservation):
        pnr_no = getattr(reservation, "pnr_no", None) or getattr(reservation, "rsv_id", None)
        if not pnr_no:
            raise KorailError("취소할 예약번호를 찾을 수 없습니다.")
        try:
            hold = getattr(reservation, "_hold", None) or self._client.get_reservation_hold(pnr_no)
            result = self._client.cancel_unpaid_hold(hold)
            return getattr(result, "str_result", None) in (None, "SUCC")
        except Exception as exc:
            raise KorailError(str(exc))

    def refund(self, ticket):
        raise KorailError("자동 환불은 안전을 위해 이 호환 패치에서 비활성화했습니다.")

    def ticket_info(self, ticket):
        return ticket
