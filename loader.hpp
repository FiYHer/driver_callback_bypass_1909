#pragma once
#include <Windows.h>

#include <iostream>

/* 安装驱动 */
unsigned long
install_driver(
	const wchar_t* drvPath,
	const wchar_t* serviceName)
{
	// 打开服务控制管理器数据库
	SC_HANDLE schSCManager = OpenSCManagerW(
		NULL,												// 目标计算机的名称,NULL：连接本地计算机上的服务控制管理器
		NULL,												// 服务控制管理器数据库的名称，NULL：打开 SERVICES_ACTIVE_DATABASE 数据库
		SC_MANAGER_ALL_ACCESS);			// 所有权限
	if (schSCManager == NULL)
		return GetLastError();

	// 创建服务对象，添加至服务控制管理器数据库
	SC_HANDLE schService = CreateServiceW(
		schSCManager,									// 服务控件管理器数据库的句柄
		serviceName,										// 要安装的服务的名称
		serviceName,										// 用户界面程序用来标识服务的显示名称
		SERVICE_ALL_ACCESS,							// 对服务的访问权限：所有全权限
		SERVICE_KERNEL_DRIVER,					// 服务类型：驱动服务
		SERVICE_DEMAND_START,					// 服务启动选项：进程调用 StartService 时启动
		SERVICE_ERROR_IGNORE,					// 如果无法启动：忽略错误继续运行
		drvPath,												// 驱动文件绝对路径，如果包含空格需要多加双引号
		NULL,													// 服务所属的负载订购组：服务不属于某个组
		NULL,													// 接收订购组唯一标记值：不接收
		NULL,													// 服务加载顺序数组：服务没有依赖项
		NULL,													// 运行服务的账户名：使用 LocalSystem 账户
		NULL);													// LocalSystem 账户密码
	if (schService == NULL)
	{
		CloseServiceHandle(schSCManager);
		return GetLastError();
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);

	return 0;
}

/* 启动服务 */
unsigned long
start_driver(
	const wchar_t* serviceName)
{
	// 打开服务控制管理器数据库
	SC_HANDLE schSCManager = OpenSCManagerW(
		NULL,													// 目标计算机的名称,NULL：连接本地计算机上的服务控制管理器
		NULL,													// 服务控制管理器数据库的名称，NULL：打开 SERVICES_ACTIVE_DATABASE 数据库
		SC_MANAGER_ALL_ACCESS);				// 所有权限
	if (schSCManager == NULL)
		return GetLastError();

	// 打开服务
	SC_HANDLE hs = OpenServiceW(
		schSCManager,						// 服务控件管理器数据库的句柄
		serviceName,							// 要打开的服务名
		SERVICE_ALL_ACCESS);			// 服务访问权限：所有权限
	if (hs == NULL)
	{
		CloseServiceHandle(schSCManager);
		return GetLastError();
	}

	// 开始服务
	if (StartServiceW(hs, 0, 0) == 0)
	{
		CloseServiceHandle(hs);
		CloseServiceHandle(schSCManager);
		return GetLastError();
	}

	CloseServiceHandle(hs);
	CloseServiceHandle(schSCManager);

	return 0;
}

/* 停止服务 */
unsigned long
stop_driver(
	const wchar_t* serviceName)
{
	// 打开服务控制管理器数据库
	SC_HANDLE schSCManager = OpenSCManagerW(
		NULL,												// 目标计算机的名称,NULL：连接本地计算机上的服务控制管理器
		NULL,												// 服务控制管理器数据库的名称，NULL：打开 SERVICES_ACTIVE_DATABASE 数据库
		SC_MANAGER_ALL_ACCESS);			// 所有权限
	if (schSCManager == NULL)
		return GetLastError();

	// 打开服务
	SC_HANDLE hs = OpenServiceW(
		schSCManager,							// 服务控件管理器数据库的句柄
		serviceName,								// 要打开的服务名
		SERVICE_ALL_ACCESS);				// 服务访问权限：所有权限
	if (hs == NULL)
	{
		CloseServiceHandle(schSCManager);
		return GetLastError();
	}

	SERVICE_STATUS status;
	if (QueryServiceStatus(hs, &status) == 0)
	{
		CloseServiceHandle(hs);
		CloseServiceHandle(schSCManager);
		return GetLastError();
	}

	if (status.dwCurrentState != SERVICE_STOPPED && status.dwCurrentState != SERVICE_STOP_PENDING)
	{
		// 发送关闭服务请求
		if (ControlService(
			hs,												// 服务句柄
			SERVICE_CONTROL_STOP,			// 控制码：通知服务应该停止
			&status										// 接收最新的服务状态信息
		) == 0)
		{
			CloseServiceHandle(hs);
			CloseServiceHandle(schSCManager);
			return GetLastError();
		}

		// 判断超时
		int timeOut = 0;
		while (status.dwCurrentState != SERVICE_STOPPED)
		{
			timeOut++;
			QueryServiceStatus(hs, &status);
			Sleep(50);
		}

		if (timeOut > 80)
		{
			CloseServiceHandle(hs);
			CloseServiceHandle(schSCManager);
			return GetLastError();
		}

		return 0;
	}

	CloseServiceHandle(hs);
	CloseServiceHandle(schSCManager);
	return true;
}

/* 卸载驱动 */
unsigned long
unload_driver(
	const wchar_t* serviceName)
{
	// 打开服务控制管理器数据库
	SC_HANDLE schSCManager = OpenSCManagerW(
		NULL,												// 目标计算机的名称,NULL：连接本地计算机上的服务控制管理器
		NULL,												// 服务控制管理器数据库的名称，NULL：打开 SERVICES_ACTIVE_DATABASE 数据库
		SC_MANAGER_ALL_ACCESS);			// 所有权限
	if (schSCManager == NULL)
		return GetLastError();

	// 打开服务
	SC_HANDLE hs = OpenServiceW(
		schSCManager,						// 服务控件管理器数据库的句柄
		serviceName,							// 要打开的服务名
		SERVICE_ALL_ACCESS);			// 服务访问权限：所有权限
	if (hs == NULL)
	{
		CloseServiceHandle(schSCManager);
		return GetLastError();
	}

	// 删除服务
	if (DeleteService(hs) == 0)
	{
		CloseServiceHandle(hs);
		CloseServiceHandle(schSCManager);
		return GetLastError();
	}

	CloseServiceHandle(hs);
	CloseServiceHandle(schSCManager);

	return 0;
}

/* 开始卸载 */
bool
start_uninstall_driver(
	const wchar_t* serviceName)
{
	stop_driver(serviceName);
	return unload_driver(serviceName) == 0;
}

/* 开始安装 */
bool
start_install_driver(
	const wchar_t* drvPath,
	const wchar_t* serviceName,
	bool uninstall = false)
{
	// 先尝试卸载
	if (uninstall)
		start_uninstall_driver(serviceName);

	// 尝试加载
	install_driver(drvPath, serviceName);
	return start_driver(serviceName) == 0;
}