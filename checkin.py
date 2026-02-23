#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本
"""

import asyncio
import json
import os
import sys
from datetime import datetime, timezone, timedelta

import ssl
import time

import httpx
from dotenv import load_dotenv
from playwright.async_api import async_playwright

from utils.config import AccountConfig, AppConfig, load_accounts_config
from utils.notify import notify

load_dotenv()

CN_TZ = timezone(timedelta(hours=8))
BALANCE_DATA_FILE = 'balance_data.json'


def load_balance_data():
	"""加载上次余额数据"""
	try:
		if os.path.exists(BALANCE_DATA_FILE):
			with open(BALANCE_DATA_FILE, 'r', encoding='utf-8') as f:
				return json.load(f)
	except Exception:
		pass
	return None


def save_balance_data(data):
	"""保存余额数据"""
	try:
		with open(BALANCE_DATA_FILE, 'w', encoding='utf-8') as f:
			json.dump(data, f, ensure_ascii=False)
	except Exception as e:
		print(f'Warning: 保存余额数据失败: {e}')


def parse_cookies(cookies_data):
	"""解析 cookies 数据"""
	if isinstance(cookies_data, dict):
		return cookies_data

	if isinstance(cookies_data, str):
		cookies_dict = {}
		for cookie in cookies_data.split(';'):
			if '=' in cookie:
				key, value = cookie.strip().split('=', 1)
				cookies_dict[key] = value
		return cookies_dict
	return {}


async def get_waf_cookies_with_playwright(account_name: str, login_url: str, required_cookies: list[str]):
	"""使用 Playwright 获取 WAF cookies（隐私模式）"""
	print(f'[PROCESSING] {account_name}: Starting browser to get WAF cookies...')

	async with async_playwright() as p:
		import tempfile

		with tempfile.TemporaryDirectory() as temp_dir:
			context = await p.chromium.launch_persistent_context(
				user_data_dir=temp_dir,
				headless=False,
				user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
				viewport={'width': 1920, 'height': 1080},
				args=[
					'--disable-blink-features=AutomationControlled',
					'--disable-dev-shm-usage',
					'--disable-web-security',
					'--disable-features=VizDisplayCompositor',
					'--no-sandbox',
				],
			)

			page = await context.new_page()

			try:
				print(f'[PROCESSING] {account_name}: Access login page to get initial cookies...')

				await page.goto(login_url, wait_until='networkidle')

				try:
					await page.wait_for_function('document.readyState === "complete"', timeout=5000)
				except Exception:
					await page.wait_for_timeout(3000)

				cookies = await page.context.cookies()

				waf_cookies = {}
				for cookie in cookies:
					cookie_name = cookie.get('name')
					cookie_value = cookie.get('value')
					if cookie_name in required_cookies and cookie_value is not None:
						waf_cookies[cookie_name] = cookie_value

				print(f'[INFO] {account_name}: Got {len(waf_cookies)} WAF cookies')

				missing_cookies = [c for c in required_cookies if c not in waf_cookies]

				if missing_cookies:
					print(f'[FAILED] {account_name}: Missing WAF cookies: {missing_cookies}')
					await context.close()
					return None

				print(f'[SUCCESS] {account_name}: Successfully got all WAF cookies')

				await context.close()

				return waf_cookies

			except Exception as e:
				print(f'[FAILED] {account_name}: Error occurred while getting WAF cookies: {e}')
				await context.close()
				return None


MAX_RETRIES = 3
RETRY_DELAY = 2


def _request_with_retry(func, *args, **kwargs):
	"""带重试的 HTTP 请求，处理临时 SSL 波动"""
	for attempt in range(MAX_RETRIES):
		try:
			return func(*args, **kwargs)
		except (ssl.SSLError, httpx.ConnectError, httpx.RemoteProtocolError) as e:
			if attempt < MAX_RETRIES - 1:
				print(f'[RETRY] Request failed ({e.__class__.__name__}), retrying ({attempt + 2}/{MAX_RETRIES})...')
				time.sleep(RETRY_DELAY)
			else:
				raise


def get_user_info(client, headers, user_info_url: str):
	"""获取用户信息"""
	try:
		response = _request_with_retry(client.get, user_info_url, headers=headers, timeout=30)

		if response.status_code == 200:
			data = response.json()
			if data.get('success'):
				user_data = data.get('data', {})
				quota = round(user_data.get('quota', 0) / 500000, 2)
				used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
				return {
					'success': True,
					'quota': quota,
					'used_quota': used_quota,
					'display': f'余额: ${quota}, 已用: ${used_quota}, 总额: ${round(quota + used_quota, 2)}',
				}
		return {'success': False, 'error': f'Failed to get user info: HTTP {response.status_code}'}
	except Exception as e:
		return {'success': False, 'error': f'Failed to get user info: {str(e)[:50]}...'}


async def prepare_cookies(account_name: str, provider_config, user_cookies: dict) -> dict | None:
	"""准备请求所需的 cookies（可能包含 WAF cookies）"""
	waf_cookies = {}

	if provider_config.needs_waf_cookies():
		login_url = f'{provider_config.domain}{provider_config.login_path}'
		waf_cookies = await get_waf_cookies_with_playwright(account_name, login_url, provider_config.waf_cookie_names)
		if not waf_cookies:
			print(f'[FAILED] {account_name}: Unable to get WAF cookies')
			return None
	else:
		print(f'[INFO] {account_name}: Bypass WAF not required, using user cookies directly')

	return {**waf_cookies, **user_cookies}


def execute_check_in(client, account_name: str, provider_config, headers: dict):
	"""执行签到请求"""
	print(f'[NETWORK] {account_name}: Executing check-in')

	checkin_headers = headers.copy()
	checkin_headers.update({'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})

	sign_in_url = f'{provider_config.domain}{provider_config.sign_in_path}'
	response = _request_with_retry(client.post, sign_in_url, headers=checkin_headers, timeout=30)

	print(f'[RESPONSE] {account_name}: Response status code {response.status_code}')

	if response.status_code == 200:
		try:
			result = response.json()
			if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
				print(f'[SUCCESS] {account_name}: Check-in successful!')
				return True

			msg = result.get('msg', result.get('message', ''))
			if '已签到' in msg or '已经签到' in msg:
				print(f'[SUCCESS] {account_name}: Already checked in today')
				return True

			print(f'[FAILED] {account_name}: Check-in failed - {msg or "Unknown error"}')
			return False
		except json.JSONDecodeError:
			if 'success' in response.text.lower():
				print(f'[SUCCESS] {account_name}: Check-in successful!')
				return True
			else:
				print(f'[FAILED] {account_name}: Check-in failed - Invalid response format')
				return False
	else:
		print(f'[FAILED] {account_name}: Check-in failed - HTTP {response.status_code}')
		return False


async def check_in_account(account: AccountConfig, account_index: int, app_config: AppConfig):
	"""为单个账号执行签到操作"""
	account_name = account.get_display_name(account_index)
	print(f'\n[PROCESSING] Starting to process {account_name}')

	provider_config = app_config.get_provider(account.provider)
	if not provider_config:
		print(f'[FAILED] {account_name}: Provider "{account.provider}" not found in configuration')
		return False, None

	print(f'[INFO] {account_name}: Using provider "{account.provider}" ({provider_config.domain})')

	user_cookies = parse_cookies(account.cookies)
	if not user_cookies:
		print(f'[FAILED] {account_name}: Invalid configuration format')
		return False, None

	all_cookies = await prepare_cookies(account_name, provider_config, user_cookies)
	if not all_cookies:
		return False, None

	client = httpx.Client(http2=True, timeout=30.0)

	try:
		client.cookies.update(all_cookies)

		headers = {
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
			'Accept': 'application/json, text/plain, */*',
			'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
			'Accept-Encoding': 'gzip, deflate',
			'Referer': provider_config.domain,
			'Origin': provider_config.domain,
			'Connection': 'keep-alive',
			'Sec-Fetch-Dest': 'empty',
			'Sec-Fetch-Mode': 'cors',
			'Sec-Fetch-Site': 'same-origin',
			provider_config.api_user_key: account.api_user,
		}

		user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'
		user_info = get_user_info(client, headers, user_info_url)

		if not user_info or not user_info.get('success'):
			error = user_info.get('error', 'Unknown error') if user_info else 'No response'
			print(f'[FAILED] {account_name}: 无法获取用户信息 - {error}')
			return False, user_info

		print(user_info['display'])

		if provider_config.needs_manual_check_in():
			success = execute_check_in(client, account_name, provider_config, headers)
			return success, user_info
		else:
			print(f'[INFO] {account_name}: Check-in completed automatically (triggered by user info request)')
			return True, user_info

	except Exception as e:
		print(f'[FAILED] {account_name}: Error occurred during check-in process - {str(e)[:50]}...')
		return False, None
	finally:
		client.close()


async def main():
	"""主函数"""
	print('[系统] AnyRouter.top 多账号自动签到脚本启动')
	print(f'[时间] 执行时间: {datetime.now(tz=CN_TZ).strftime("%Y-%m-%d %H:%M:%S")} (UTC+8)')

	app_config = AppConfig.load_from_env()
	print(f'[信息] 已加载 {len(app_config.providers)} 个服务商配置')

	accounts = load_accounts_config()
	if not accounts:
		print('[失败] 无法加载账号配置，程序退出')
		sys.exit(1)

	print(f'[信息] 发现 {len(accounts)} 个账号配置')

	last_balance_data = load_balance_data()

	success_count = 0
	total_count = len(accounts)
	current_balances = {}
	need_notify = False
	balance_changed = False
	failed_accounts = []

	for i, account in enumerate(accounts):
		account_key = f'account_{i + 1}'
		try:
			success, user_info = await check_in_account(account, i, app_config)
			if success:
				success_count += 1

			if not success:
				need_notify = True
				account_name = account.get_display_name(i)
				print(f'[通知] {account_name} 签到失败，将发送通知')
				error_info = ''
				if user_info and user_info.get('success'):
					error_info = user_info['display']
				elif user_info:
					error_info = user_info.get('error', '未知错误')
				failed_accounts.append((account_name, error_info))

			if user_info and user_info.get('success'):
				current_quota = user_info['quota']
				current_used = user_info['used_quota']
				current_balances[account_key] = {
					'quota': current_quota,
					'used': current_used,
					'total': round(current_quota + current_used, 2),
				}

		except Exception as e:
			account_name = account.get_display_name(i)
			print(f'[失败] {account_name} 处理异常: {e}')
			need_notify = True
			failed_accounts.append((account_name, f'异常: {str(e)[:50]}...'))

	# 检查余额变化
	if current_balances:
		if last_balance_data is None:
			balance_changed = True
			need_notify = True
			print('[通知] 首次运行，将发送当前余额通知')
		else:
			for key, bal in current_balances.items():
				if key not in last_balance_data:
					balance_changed = True
					need_notify = True
					break
				prev = last_balance_data[key]
				prev_total = round(prev.get('total', prev.get('quota', 0) + prev.get('used', 0)), 2)
				diff = round(bal['total'] - prev_total, 2)
				if diff != 0:
					balance_changed = True
					need_notify = True
					break
			if balance_changed:
				print('[通知] 检测到余额变化，将发送通知')
			else:
				print('[信息] 未检测到余额变化')

	# 保存当前余额数据
	if current_balances:
		save_balance_data(current_balances)

	if need_notify:
		# 构建通知内容
		time_info = f'[时间] 执行时间: {datetime.now(tz=CN_TZ).strftime("%Y-%m-%d %H:%M:%S")} (UTC+8)'

		# 额度信息
		balance_lines = []
		total_quota = 0.0
		total_used = 0.0
		for i, account in enumerate(accounts):
			account_key = f'account_{i + 1}'
			if account_key in current_balances:
				account_name = account.get_display_name(i)
				provider_name = account.provider
				bal = current_balances[account_key]
				total_quota += bal['quota']
				total_used += bal['used']
				line = f'[额度] {account_name} ({provider_name})'
				line += f'\n余额: ${bal["quota"]}, 已用: ${bal["used"]}, 总额: ${bal["total"]}'
				if last_balance_data and account_key in last_balance_data:
					prev = last_balance_data[account_key]
					prev_total = round(prev.get('total', prev.get('quota', 0) + prev.get('used', 0)), 2)
					diff = round(bal['total'] - prev_total, 2)
					if diff > 0:
						line += f'\n较上次: 总额增加 ${diff} (上次总额: ${prev_total})'
					elif diff < 0:
						line += f'\n较上次: 总额减少 ${abs(diff)} (上次总额: ${prev_total})'
					else:
						line += f'\n较上次: 总额无变化 (${bal["total"]})'
				else:
					line += '\n较上次: 首次记录'
				balance_lines.append(line)

		# 总额度汇总（多个账号时显示）
		if len(balance_lines) > 1:
			total_all = round(total_quota + total_used, 2)
			balance_lines.append(
				f'[汇总] 全部站点\n余额: ${round(total_quota, 2)}, 已用: ${round(total_used, 2)}, 总额: ${total_all}'
			)

		# 失败账号信息
		fail_lines = []
		for name, error in failed_accounts:
			fail_line = f'[失败] {name}'
			if error:
				fail_line += f'\n{error}'
			fail_lines.append(fail_line)

		# 统计
		summary = [
			'[统计] 签到结果:',
			f'[成功] 成功: {success_count}/{total_count}',
			f'[失败] 失败: {total_count - success_count}/{total_count}',
		]

		if success_count == total_count:
			summary.append('[成功] 所有账号签到成功!')
		elif success_count > 0:
			summary.append('[警告] 部分账号签到成功')
		else:
			summary.append('[错误] 所有账号签到失败')

		# 组合通知内容
		sections = [time_info]
		if balance_lines:
			sections.append('\n'.join(balance_lines))
		if fail_lines:
			sections.append('\n'.join(fail_lines))
		sections.append('\n'.join(summary))

		notify_content = '\n\n'.join(sections)
		print(notify_content)
		notify.push_message('AnyRouter 签到通知', notify_content, msg_type='text')
		print('[通知] 通知已发送')
	else:
		print('[信息] 所有账号签到成功且余额无变化，跳过通知')

	# 设置退出码
	sys.exit(0 if success_count > 0 else 1)


def run_main():
	"""运行主函数的包装函数"""
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print('\n[WARNING] Program interrupted by user')
		sys.exit(1)
	except Exception as e:
		print(f'\n[FAILED] Error occurred during program execution: {e}')
		sys.exit(1)


if __name__ == '__main__':
	run_main()
