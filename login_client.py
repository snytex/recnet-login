import requests
import capsolver

capsolver.api_key = "YOUR CAPSOLVER KEY"

class RecNetLogin:
    def __init__(self):
        self.base_url = "https://rec.net"
        self.login_url = "https://auth.rec.net/Account/Login"
        self.site_key = "6LeZdgQmAAAAAFtXHuu-1boPxaOKBW7HCRzI4tIV"
        self.session = requests.Session()

        self.headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en",
            "Cache-Control": "max-age=0",
            "Connection": "keep-alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "auth.rec.net",
            "Origin": "https://auth.rec.net",
            "Referer": "https://auth.rec.net/Account/Login",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        }

    def get_anti_forgery(self):
        response = self.session.get(self.login_url, headers=self.headers)
        cookies = response.cookies.get_dict()
        anti_forgery = cookies.get(".AspNetCore.Antiforgery.cdV5uW_Ejgc")
        return anti_forgery

    def get_req_token(self):
        response = self.session.get(self.login_url, headers=self.headers)
        response_text = response.text
        try:
            token = response_text.split('name="__RequestVerificationToken" type="hidden" value="')[1].split('"')[0]
            return token
        except IndexError:
            raise Exception("Unable to find __RequestVerificationToken in the HTML response.")

    def solve_captcha(self):
        solution = capsolver.solve({
            "type": "ReCaptchaV2EnterpriseTaskProxyLess",
            "websiteKey": self.site_key,
            "websiteURL": self.login_url,
        })
        return solution.get("gRecaptchaResponse")

    def login(self, username, password):
        anti_forgery_token = self.get_anti_forgery()
        req_token = self.get_req_token()
        captcha_solution = self.solve_captcha()

        payload = {
            "Input.Username": username,
            "Input.Password": password,
            "g-recaptcha-response": captcha_solution,
            "Input.RememberMe": "true",
            "button": "login",
            "__RequestVerificationToken": req_token,
            "Input.RememberMe": "false"
        }

        self.session.cookies.set(".AspNetCore.Antiforgery.cdV5uW_Ejgc", anti_forgery_token)

        response = self.session.post(self.login_url, data=payload, headers=self.headers)
        return response.text

if __name__ == "__main__":
    r = RecNetLogin()
    login = r.login("grtgrsh", "htrshhrs")
    print(login)