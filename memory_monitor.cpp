#include <direct.h>
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
#include <Psapi.h>
#pragma comment(lib, "psapi.lib")

int finish()
{
	std::string cmd;
	while (std::cin >> cmd)
	{
		if ("exit" == cmd || "quit" == cmd || "q" == cmd)
		{
			std::cout << "exit application !!!" << std::endl;
			break;
		}
	}
	return 0;
}

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

/* 查询进程内存 */
void queryProcessMemory(DWORD processId, unsigned long& workingSetSize, unsigned long& workSetShared, unsigned long& workSetPrivate) {
	workingSetSize = workSetShared = workSetPrivate = 0;
	adjustPurview();
	/* 获取进程句柄 */
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
	if (!hProcess) {
		return;
	}
	/* 获取工作集(内存) */
	PROCESS_MEMORY_COUNTERS pmc;
	GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc));
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
	/* 关闭进程句柄 */
	CloseHandle(hProcess);
}

/* 定时监控 */
void threadHandler(unsigned int pid, unsigned int memorySize, unsigned int frequence) {
	int preWorkingSetSizeKb = 0;
	int preWorkSetSharedKb = 0;
	int preWorkSetPrivateKb = 0;
	bool isInit = true;
	while (1) {
		unsigned long workingSetSize, workSetShared, workSetPrivate;
		queryProcessMemory(pid, workingSetSize, workSetShared, workSetPrivate);
		if (0 == workingSetSize) {
			Logger::getInstance()->print("Can't find process with pid[" + std::to_string(pid) + "]", "", false, true);
			break;
		}
		/* 字节转Kb */
		int workingSetSizeKb = workingSetSize / 1024;
		int workSetSharedKb = workSetShared / 1024;
		int workSetPrivateKb = workSetPrivate / 1024;
		/* 判断内存是增长还是减少 */
		bool up = (workingSetSizeKb > preWorkingSetSizeKb);
		/* 计算内存差值(单位:Kb) */
		int diffWorkingSetSizeKb = std::abs(workingSetSizeKb - preWorkingSetSizeKb);
		int diffWorkSetSharedKb = std::abs(workSetSharedKb - preWorkSetSharedKb);
		int diffWorkSetPrivateKb = std::abs(workSetPrivateKb - preWorkSetPrivateKb);
		if ((unsigned int)diffWorkingSetSizeKb >= memorySize) {	/* 内存变动超过监控值 */
			/* 缓存当前内存值 */
			preWorkingSetSizeKb = workingSetSizeKb;
			preWorkSetSharedKb = workSetSharedKb;
			preWorkSetPrivateKb = workSetPrivateKb;
			/* Kb转Mb */
			double workingSetSizeMb = (double)workingSetSizeKb / 1024;
			double workSetSharedMb = (double)workSetSharedKb / 1024;
			double workSetPrivateMb = (double)workSetPrivateKb / 1024;
			/* 打印日志 */
			try {
				char buf[256] = { 0 };
				if (isInit) {	/* 首次 */
					isInit = false;
					sprintf_s(buf, "Now Memory, WorkingSetSize[%d Kb, %0.1f Mb], WorkSetShared[%d Kb, %0.1f Mb], WorkSetPrivate[%d Kb, %0.1f Mb]",
						workingSetSizeKb, workingSetSizeMb, workSetSharedKb, workSetSharedMb, workSetPrivateKb, workSetPrivateMb);
				}
				else {	/* 非首次 */
					/* 设置内存增长/减少符号 */
					std::string flag = up ? "+" : "-";
					/* 内存差值单位Kb转Mb */
					double diffWorkingSetSizeMb = (double)diffWorkingSetSizeKb / 1024;
					double diffWorkSetSharedMb = (double)diffWorkSetSharedKb / 1024;
					double diffWorkSetPrivateMb = (double)diffWorkSetPrivateKb / 1024;
					sprintf_s(buf, "WorkingSet[(%d Kb, %0.1f Mb), %s(%d Kb, %0.1f Mb)], Shared[(%d Kb, %0.1f Mb), %s(%d Kb, %0.1f Mb)], Private[(%d Kb, %0.1f Mb), %s(%d Kb, %0.1f Mb)]",
						workingSetSizeKb, workingSetSizeMb, flag.c_str(), diffWorkingSetSizeKb, diffWorkingSetSizeMb,
						workSetSharedKb, workSetSharedMb, flag.c_str(), diffWorkSetSharedKb, diffWorkSetSharedMb,
						workSetPrivateKb, workSetPrivateMb, flag.c_str(), diffWorkSetPrivateKb, diffWorkSetPrivateMb);
				}
				Logger::getInstance()->print(buf, "", false, true);
			}
			catch (const std::exception& e) {
				Logger::getInstance()->print(e.what(), "", false, true);
			}
			catch (...) {
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
	std::cout << "Enter 'q' or 'exit' or 'quit' to finish application: " << std::endl;
	Logger::getInstance()->print("Start monitor memory size", "", false, true);
	double sizeMb = (double)memorySize / 1024;
	char buf[64] = { 0 };
	sprintf_s(buf, "memory size: %d Kb, %0.1f Mb", memorySize, sizeMb);
	Logger::getInstance()->print(buf, "", false, true);
	Logger::getInstance()->print("frequence: " + std::to_string(frequence) + " s", "", false, true);
	/* 开辟子线程 */
	std::thread th(threadHandler, pid, memorySize, frequence);
	th.detach();
	/* 等待退出 */
	return finish();
}
