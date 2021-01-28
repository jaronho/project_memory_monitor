#include <direct.h>
#include <math.h>
#include <time.h>
#include <io.h>
#include <exception>
#include <iostream>
#include <string>
#include <thread>
#include "cmdline/cmdline.h"
#include "logger/Logger.h"
/* 下面头文件在最后面包含 */
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#pragma comment(lib, "psapi.lib")

unsigned long long generateUID(void) {
	static int sY = 0, sM = 0, sD = 0, sH = 0, sMM = 0, sS = 0, sIdx = 1;
	time_t t = time(nullptr);
	struct tm* dt = localtime(&t);
	int year = 1900 + dt->tm_year, mon = 1 + dt->tm_mon, mday = dt->tm_mday, hour = dt->tm_hour, min = dt->tm_min, sec = dt->tm_sec;
	if (year == sY && mon == sM && mday == sD && hour == sH && min == sMM && sec == sS) {
		sIdx++;
	}
	else {
		sY = year; sM = mon; sD = mday; sH = hour; sMM = min; sS = sec; sIdx = 1;
	}
	return (unsigned long long)sY * 10000000000000 + (unsigned long long)sM * 100000000000 + (unsigned long long)sD * 1000000000 +
		(unsigned long long)sH * 10000000 + (unsigned long long)sMM * 100000 + (unsigned long long)sS * 1000 + (unsigned long long)sIdx;
}

std::string generateFilename(const std::string& extname) {
	char filename[64] = { 0 };
	sprintf(filename, "%llu%s", generateUID(), extname.empty() ? "" : ('.' == extname.at(0) ? extname.c_str() : ('.' + extname).c_str()));
	return filename;
}

/* 提升进程权限 */
bool adjustPurview() {
	TOKEN_PRIVILEGES tokenPrivileges;
	HANDLE hToken;

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tokenPrivileges.Privileges[0].Luid);
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	BOOL ret = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, 0, NULL, NULL);

	CloseHandle(hToken);
	return (TRUE == ret);
}

/* 查询进程信息 */
void queryProcessInfo(unsigned long processId,
	unsigned long& workingSetSize, unsigned long& workSetPrivate, unsigned long& workSetShared,
	unsigned long& handles,
	unsigned long& threads) {
	workingSetSize = workSetPrivate = workSetShared = 0;
	handles = 0;
	threads = 0;
	adjustPurview();
	/* 获取进程句柄 */
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
	if (!hProcess) {
		return;
	}
	/* 查询工作集(内存) */
	PROCESS_MEMORY_COUNTERS pmc;
	GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc));
	if (0 == pmc.QuotaPagedPoolUsage && 0 == pmc.QuotaNonPagedPoolUsage) {	/* 视为进程退出 */
		CloseHandle(hProcess);
		return;
	}
	workingSetSize = pmc.WorkingSetSize; /* 工作集(内存)(单位:字节): 进程当前正在使用的物理内存量, =内存(专用工作集)+内存(共享工作集) */
	/* 获取系统分页大小(单位:字节) */
	static SIZE_T s_pageSize = 0;
	if (0 == s_pageSize) {
		PERFORMANCE_INFORMATION performanceInfo;
		memset(&performanceInfo, 0, sizeof(performanceInfo));
		if (GetPerformanceInfo(&performanceInfo, sizeof(performanceInfo))) {
			s_pageSize = performanceInfo.PageSize;
		}
	}
	/* 查询工作集 */
	if (s_pageSize > 0) {
		PSAPI_WORKING_SET_INFORMATION workSetInfo;
		memset(&workSetInfo, 0, sizeof(workSetInfo));
		PSAPI_WORKING_SET_BLOCK* workSetBlock = workSetInfo.WorkingSetInfo;
		PBYTE pByte = NULL;
		BOOL queryRet = TRUE;
		if (!QueryWorkingSet(hProcess, &workSetInfo, sizeof(workSetInfo))) {	/* 获取实际缓冲区大小 */
			if (ERROR_BAD_LENGTH == GetLastError()) {	/* 需要重新分配缓冲区 */
				DWORD realSize = sizeof(workSetInfo.NumberOfEntries) + workSetInfo.NumberOfEntries * sizeof(PSAPI_WORKING_SET_BLOCK);
				try {
					pByte = new BYTE[realSize];
					memset(pByte, 0, realSize);
					workSetBlock = (PSAPI_WORKING_SET_BLOCK*)(pByte + sizeof(workSetInfo.NumberOfEntries));
					if (!QueryWorkingSet(hProcess, pByte, realSize))	/* 重新查询 */
					{
						queryRet = FALSE;
					}
				}
				catch (char* e) {	/* 内存分配失败 */
					(void)e;
					queryRet = FALSE;
				}
				catch (...) {
					queryRet = FALSE;
				}
			}
			else {
				queryRet = FALSE;
			}
		}
		if (queryRet) {
			for (ULONG_PTR i = 0; i < workSetInfo.NumberOfEntries; ++i)
			{
				if (workSetBlock[i].Shared) {	/* 共享页 */
					workSetShared += s_pageSize;	/* 内存(共享工作集): 由该进程所使用且可与其他进程共享的物理内存量 */
				}
				else {	/* 非共享页 */
					workSetPrivate += s_pageSize;	/* 内存(专用工作集): 由该进程所使用而其他进程无法使用的物理内存量 */
				}
			}
		}
		/* 需要最后清理内存, 否则会出错 */
		if (pByte) {
			delete[] pByte;
			pByte = NULL;
		}
	}
	/* 查询句柄数 */
	GetProcessHandleCount(hProcess, &handles);
	/* 查询线程数 */
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE != hProcessSnap)
	{
		char szFilePath[MAX_PATH] = { 0 };
		PROCESSENTRY32 stProcessEntry32 = { 0 };
		stProcessEntry32.dwSize = sizeof(stProcessEntry32);
		BOOL bSucceed = Process32First(hProcessSnap, &stProcessEntry32);;
		for (;;)
		{
			if (!bSucceed) {
				break;
			}
			if (stProcessEntry32.th32ProcessID == processId)
			{
				threads = stProcessEntry32.cntThreads;
				break;
			}
			bSucceed = Process32Next(hProcessSnap, &stProcessEntry32);
		}
		CloseHandle(hProcessSnap);
	}
	/* 关闭进程句柄 */
	CloseHandle(hProcess);
}

/* 监控句柄 */
void monitorHandler(unsigned int pid, unsigned int memorySize, unsigned int frequence) {
	int preWorkingSetSizeKb = 0;
	int preWorkSetPrivateKb = 0;
	int preWorkSetSharedKb = 0;
	bool isInit = true;
	while (1) {
		unsigned long workingSetSize, workSetPrivate, workSetShared;
		unsigned long handles;
		unsigned long threads;
		queryProcessInfo(pid, workingSetSize, workSetPrivate, workSetShared, handles, threads);
		if (0 == workingSetSize) {
			Logger::getInstance()->print("", "", false, false);
			Logger::getInstance()->print("Can't find process with pid[" + std::to_string(pid) + "]", "", false, true);
			break;
		}
		if (0 == workSetPrivate || 0 == workSetShared) {
			continue;
		}
		/* 字节转Kb */
		int workingSetSizeKb = workingSetSize / 1024;
		int workSetPrivateKb = workSetPrivate / 1024;
		int workSetSharedKb = workSetShared / 1024;
		/* 计算内存差值(单位:Kb) */
		int diffWorkingSetSizeKb = workingSetSizeKb - preWorkingSetSizeKb;
		int diffWorkSetPrivateKb = workSetPrivateKb - preWorkSetPrivateKb;
		int diffWorkSetSharedKb = workSetSharedKb - preWorkSetSharedKb;
		if ((unsigned int)abs(diffWorkingSetSizeKb) >= memorySize) {	/* 内存变动超过监控值 */
			/* 缓存当前内存值 */
			preWorkingSetSizeKb = workingSetSizeKb;
			preWorkSetPrivateKb = workSetPrivateKb;
			preWorkSetSharedKb = workSetSharedKb;
			/* Kb转Mb */
			double workingSetSizeMb = (double)workingSetSizeKb / 1024;
			double workSetPrivateMb = (double)workSetPrivateKb / 1024;
			double workSetSharedMb = (double)workSetSharedKb / 1024;
			/* 打印日志 */
			try {
				char buf[256] = { 0 };
				if (isInit) {	/* 首次 */
					isInit = false;
					sprintf_s(buf, "Memory: WorkingSet %0.1f Mb(%d Kb), Private %0.1f Mb(%d Kb), Shared %0.1f Mb(%d Kb)",
						workingSetSizeMb, workingSetSizeKb, workSetPrivateMb, workSetPrivateKb, workSetSharedMb, workSetSharedKb);
					Logger::getInstance()->print(buf, "", false, true);
					memset(buf, 0, sizeof(buf));
					sprintf_s(buf, "Handles: %d", handles);
					Logger::getInstance()->print(buf, "", false, true);
					memset(buf, 0, sizeof(buf));
					sprintf_s(buf, "Threads: %d", threads);
					Logger::getInstance()->print(buf, "", false, true);
					Logger::getInstance()->print("", "", false, false);
				}
				else {	/* 非首次 */
					/* 内存差值单位Kb转Mb */
					double diffWorkingSetSizeMb = (double)diffWorkingSetSizeKb / 1024;
					double diffWorkSetPrivateMb = (double)diffWorkSetPrivateKb / 1024;
					double diffWorkSetSharedMb = (double)diffWorkSetSharedKb / 1024;
					Logger::getInstance()->print("--------------------------------------------------------------------------------", "", false, true);
					if (0 == diffWorkingSetSizeKb) {
						sprintf_s(buf, "                     Memory: WorkingSet %0.1f Mb(%d Kb)", workingSetSizeMb, workingSetSizeKb);
					}
					else {
						sprintf_s(buf, "                     Memory: WorkingSet %0.1f Mb(%d Kb), %s%0.1f Mb(%d Kb)",
							workingSetSizeMb, workingSetSizeKb, diffWorkingSetSizeKb > 0 ? "+" : "-", abs(diffWorkingSetSizeMb), abs(diffWorkingSetSizeKb));
					}
					Logger::getInstance()->print(buf, "", false, false);
					memset(buf, 0, sizeof(buf));
					if (0 == diffWorkSetPrivateKb) {
						sprintf_s(buf, "                                Private %0.1f Mb(%d Kb)", workSetPrivateMb, workSetPrivateKb);
					}
					else {
						sprintf_s(buf, "                                Private %0.1f Mb(%d Kb), %s%0.1f Mb(%d Kb)",
							workSetPrivateMb, workSetPrivateKb, diffWorkSetPrivateKb > 0 ? "+" : "-", abs(diffWorkSetPrivateMb), abs(diffWorkSetPrivateKb));
					}
					Logger::getInstance()->print(buf, "", false, false);
					memset(buf, 0, sizeof(buf));
					if (0 == diffWorkSetSharedKb) {
						sprintf_s(buf, "                                 Shared %0.1f Mb(%d Kb)", workSetSharedMb, workSetSharedKb);
					}
					else {
						sprintf_s(buf, "                                 Shared %0.1f Mb(%d Kb), %s%0.1f Mb(%d Kb)",
							workSetSharedMb, workSetSharedKb, diffWorkSetSharedKb > 0 ? "+" : "-", abs(diffWorkSetSharedMb), abs(diffWorkSetSharedKb));
					}
					Logger::getInstance()->print(buf, "", false, false);
					memset(buf, 0, sizeof(buf));
					sprintf_s(buf, "                     Handles: %d", handles);
					Logger::getInstance()->print(buf, "", false, false);
					memset(buf, 0, sizeof(buf));
					sprintf_s(buf, "                     Threads: %d", threads);
					Logger::getInstance()->print(buf, "", false, false);
				}

			}
			catch (const std::exception& e) {
				Logger::getInstance()->print("", "", false, false);
				Logger::getInstance()->print("execption: " + std::string(e.what()), "", false, true);
			}
			catch (...) {
				Logger::getInstance()->print("", "", false, false);
				Logger::getInstance()->print("unknow exception", "", false, true);
			}

		}
		std::this_thread::sleep_for(std::chrono::seconds(frequence));
	}
}

int main(int argc, char* argv[]) {
	/* 命令行解析 */
	cmdline::parser cl;
	cl.add<unsigned int>("pid", 'p', "process id", true);
	cl.add<unsigned int>("msize", 'm', "monitor value for memory size(Kb) change", false, 1, cmdline::range(1, 102400)); /* 1Kb~100Mb */
	cl.add<unsigned int>("freq", 'f', "frequence(Seconds)", false, 1, cmdline::range(1, 86400));	/* 1s~1天 */
	cl.add("help", 0, "print this message");
	cl.set_program_name("memory_monitor");
	if (!cl.parse(argc, argv)) {
		std::cerr << cl.error() << std::endl << cl.usage();
		return 0;
	}
	if (cl.exist("help")) {
		std::cerr << cl.usage();
		return 0;
	}
	/* 进程id */
	unsigned int pid = 0;
	if (cl.exist("pid")) {
		pid = cl.get<unsigned int>("pid");
	}
	if (0 == pid)
	{
		std::cerr << "pid is 0" << std::endl;
		return 0;
	}
	/* 内存监控大小 */
	unsigned int memorySize = 0;
	if (cl.exist("msize")) {
		memorySize = cl.get<unsigned int>("msize");
	}
	if (0 == memorySize)
	{
		memorySize = 512;
	}
	/* 监控频率 */
	unsigned int frequence = 0;
	if (cl.exist("freq")) {
		frequence = cl.get<unsigned int>("freq");
	}
	if (0 == frequence)
	{
		frequence = 1;
	}
	/* 设置输出文件名 */
	std::string dirname = "log/";
	if (0 != _access(dirname.c_str(), 0)) {
		if (0 != _mkdir(dirname.c_str())) {
			dirname.clear();
		}
	}
	std::string filename = dirname + "pid[" + std::to_string(pid) + "]-" + generateFilename(".log");
	Logger::getInstance()->setFilename(filename);
	/* 初始打印 */
	Logger::getInstance()->print("Start monitor memory size", "", false, true);
	double sizeMb = (double)memorySize / 1024;
	char buf[64] = { 0 };
	sprintf_s(buf, "memory size: %0.1f Mb(%d Kb)", sizeMb, memorySize);
	Logger::getInstance()->print(buf, "", false, true);
	Logger::getInstance()->print("frequence: " + std::to_string(frequence) + " s", "", false, true);
	/* 监控 */
	monitorHandler(pid, memorySize, frequence);
	return 0;
}

