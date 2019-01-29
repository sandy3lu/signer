package com.yunjing.eurekaclient2.common.base;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * @ClassName CmdExeUtil
 * @Description 指令执行工具类
 * @Author scyking
 * @Date 2019/1/11 10:59
 * @Version 1.0
 */
public class CmdExeUtil {

    /**
     * 判断系统是否是windows系统
     *
     * @return
     */
    private static boolean isWindowsSystem() {
        String systemName = System.getProperty("os.name");
        return systemName.toLowerCase().contains("windows");
    }

    /**
     * 执行指令（目前仅区别windows系统与linux系统）
     *
     * @param cmd
     */
    public static void exeCmd(String cmd) throws IOException, InterruptedException {
        if (isWindowsSystem()) {
            winCmd(cmd);
        } else {
            linuxCmd(cmd);
        }
    }

    /**
     * windows下执行指令（异步）
     */
    public static void winCmd(String cmd) throws IOException, InterruptedException {
        String[] myCmd = {"cmd", "/C", cmd};
        System.out.println(myCmd.toString());
        Process proc = Runtime.getRuntime().exec(myCmd);
        InputStreamReader isr = new InputStreamReader(proc.getErrorStream());
        BufferedReader br = new BufferedReader(isr);
        String line = null;
        System.out.println("<error></error>");
        while ((line = br.readLine()) != null) {
            System.out.println(line);
        }
        int exitVal = proc.waitFor();
        isr=new InputStreamReader(proc.getInputStream());
        br=new BufferedReader(isr);
        line=null;
        System.out.println("<info></info>");
        while((line=br.readLine())!=null)
        {
            System.out.println(line);
        }

        System.out.println("Process exitValue: " + exitVal);
    }

    /**
     * linux下执行指令（异步）
     */
    public static void linuxCmd(String cmd) throws IOException, InterruptedException {
        String[] myCmd = {"/bin/sh", "-c", cmd};
        Process proc = Runtime.getRuntime().exec(myCmd);
        proc.waitFor();
    }


    public static void main(String[] args) throws IOException, InterruptedException {
        winCmd("mysqldump -u root -proot sm_sign dict_constant > D:/mysql.sql");
    }
}

