from tkinter import *
from Crypto.Cipher import AES
import tkinter.messagebox
import tkinter.filedialog
from tkinter import ttk
import os
import sys

speed=1024*1024#默认速度1M每次的速度

filelist=[]#存放显示在列表里的文件名的地方，用于给用户显示
real_filelist=[]#存放绝对路径的地方，用于处理其他位置的文件加密
AES_BLOCK_SIZE = AES.block_size  # AES 加密数据块大小, 只能是16
AES_KEY_SIZE = 16  # AES 密钥长度（单位字节），可选 16、24、32，对应 128、192、256 位密钥



def PadTest(bytes):
    while len(bytes) % AES_BLOCK_SIZE != 0:  # 循环直到补齐 AES_BLOCK_SIZE 的倍数
        bytes += ' '.encode()  # 通过补空格（不影响源文件的可读）来补齐
    return bytes  # 返回补齐后的字节列表


def PadKey(key):
    if len(key) > AES_KEY_SIZE:  # 如果密钥长度超过 AES_KEY_SIZE
        return key[:AES_KEY_SIZE]  # 截取前面部分作为密钥并返回
    while len(key) % AES_KEY_SIZE != 0:  # 不到 AES_KEY_SIZE 长度则补齐
        key += ' '.encode()  # 补齐的字符可用任意字符代替
    return key  # 返回补齐后的密钥


# AES 加密
def EnCrypt(key, bytes):
    myCipher = AES.new(key, AES.MODE_ECB)  # 新建一个 AES 算法实例，使用 ECB（电子密码本）模式
    encryptData = myCipher.encrypt(bytes)  # 调用加密方法，得到加密后的数据
    return encryptData  # 返回加密数据


# AES 解密
def DeCrypt(key, encryptData):
    myCipher = AES.new(key, AES.MODE_ECB)  # 新建一个 AES 算法实例，使用 ECB（电子密码本）模式
    bytes = myCipher.decrypt(encryptData)  # 调用解密方法，得到解密后的数据
    return bytes  # 返回解密数据



def ini():
      Lstbox1.delete(0,END)
      list_items = filelist
      for item in list_items:
           Lstbox1.insert(END,item)


def lock_one_file():
    key=entry.get()
    if key=="":
        tkinter.messagebox.showerror("AES文件加密","密码不能为空")
    else:
      key = PadKey(key.encode())
      if Lstbox1.curselection()==():
          tkinter.messagebox.showerror("AES文件加密","未选择任何文件！")
          return 0
      else:
          filename=real_filelist[int(Lstbox1.curselection()[0])].split("/")[-1]
      if filename.split(".")[-1]=="encode":
          if tkinter.messagebox.askquestion("AES文件加密器", "文件为有加密文件，二次加密可能会导致无法正常解密文件，是否进行二次加密？") == 'yes':
              if not os.path.exists("encode"):
                  os.makedirs("encode")
              try:
                  filesize = os.path.getsize(real_filelist[int(Lstbox1.curselection()[0])])
              except:
                  tkinter.messagebox.showerror("AES文件加密器","文件无效！")
                  del real_filelist[Lstbox1.curselection()[0]]
                  del filelist[Lstbox1.curselection()[0]]
                  Lstbox1.delete(Lstbox1.curselection())
                  ini()
                  return 0
              with open(real_filelist[int(Lstbox1.curselection()[0])], "rb") as f:
                  switch_contralor(False)
                  progressbar = ttk.Progressbar(frame5)
                  progressbar['maximum'] = filesize
                  progressbar.pack()
                  if os.path.exists("encode/" + filelist[Lstbox1.curselection()[0]].split(".")[0] + ".encode"):
                      os.remove("encode/" + filelist[Lstbox1.curselection()[0]].split(".")[0] + ".encode")
                  new_file = open("encode/" + filelist[Lstbox1.curselection()[0]].split(".")[0] + ".encode", "ab")
                  new_file.write(b'******' + EnCrypt(key, b'myfile/0/0/0/0/0') + b'******')
                  new_file.close()
                  for i in range(0, filesize, speed):
                      old_file = f.read(speed)
                      new_file = open("encode/" + filelist[Lstbox1.curselection()[0]].split(".")[0] + ".encode", "ab")
                      old_file = PadTest(old_file)
                      new_file.write(EnCrypt(key, old_file))
                      new_file.close()
                      if not old_file:
                          break
                      progressbar['value'] = i
                      root.update()  # 更新主窗口，使进度条显示更新
              new_file = open("encode/" + filelist[Lstbox1.curselection()[0]].split(".")[0] + ".encode", "ab")
              old_file_name = real_filelist[int(Lstbox1.curselection()[0])].split("/")[-1]
              new_file.write(b'//////' + old_file_name.encode())
              new_file.close()
              tkinter.messagebox.showinfo("AES文件加密", "加密成功！")
              switch_contralor(True)
              progressbar.pack_forget()
          else:
              return 0
      else:
          if not os.path.exists("encode"):
              os.makedirs("encode")
          try:
              filesize = os.path.getsize(real_filelist[int(Lstbox1.curselection()[0])])
          except:
              tkinter.messagebox.showerror("AES文件加密器", "文件无效！")
              del real_filelist[Lstbox1.curselection()[0]]
              del filelist[Lstbox1.curselection()[0]]
              Lstbox1.delete(Lstbox1.curselection())
              ini()
              return 0
          with open(real_filelist[int(Lstbox1.curselection()[0])], "rb") as f:
              switch_contralor(False)
              progressbar = ttk.Progressbar(frame5)
              progressbar['maximum'] = filesize
              progressbar.pack()
              if os.path.exists("encode/" + filelist[Lstbox1.curselection()[0]].split(".")[0] + ".encode"):
                  os.remove("encode/" + filelist[Lstbox1.curselection()[0]].split(".")[0] + ".encode")
              new_file = open("encode/" + filelist[Lstbox1.curselection()[0]].split(".")[0] + ".encode", "ab")
              new_file.write(b'******'+EnCrypt(key, b'myfile/0/0/0/0/0')+b'******')
              new_file.close()
              for i in range(0, filesize, speed):
                  old_file = f.read(speed)
                  new_file = open("encode/" + filelist[Lstbox1.curselection()[0]].split(".")[0] + ".encode", "ab")
                  old_file = PadTest(old_file)
                  new_file.write(EnCrypt(key, old_file))
                  new_file.close()
                  if not old_file:
                      break
                  progressbar['value'] = i
                  root.update()  # 更新主窗口，使进度条显示更新
          new_file = open("encode/" + filelist[Lstbox1.curselection()[0]].split(".")[0] + ".encode", "ab")
          old_file_name = real_filelist[int(Lstbox1.curselection()[0])].split("/")[-1]
          new_file.write(b'//////' + old_file_name.encode())
          new_file.close()
          tkinter.messagebox.showinfo("AES文件加密", "加密成功！")
          switch_contralor(True)
          progressbar.pack_forget()
          os.popen("explorer encode")



def lock_all_file():
    key=entry.get()
    if key=="":
        tkinter.messagebox.showerror("AES文件加密","密码不能为空")
    else:
      key = PadKey(key.encode())
      if len(real_filelist)==0:
          tkinter.messagebox.showerror("AES文件加密","无可加密文件")
      else:
        if not os.path.exists("encode_files"):
              os.makedirs("encode_files")
        for i in real_filelist:
          filename = i.split("/")[-1]
          if filename.split(".")[-1] == "encode":
            if tkinter.messagebox.askquestion("AES文件加密器", "文件列表中有加密文件，二次加密可能会导致无法正常解密文件，是否进行二次加密？") == 'yes':
                two_time_encryption = True
                break
            else:
                two_time_encryption = False
                break
        count = 0
        error_file = 0
        switch_contralor(False)
        for i in real_filelist:
                filename = i.split("/")[-1]
                if filename.split(".")[-1] == "encode" and not two_time_encryption:
                    continue
                try:
                    filesize = os.path.getsize(i)
                except:
                    real_filelist.remove(i)
                    filelist.remove(filename)
                    continue
                    error_file=error_file+1
                with open(i, "rb") as f:
                    progressbar = ttk.Progressbar(frame5)
                    progressbar['maximum'] = filesize
                    progressbar.pack()
                    if os.path.exists("encode_files/" + filename.split(".")[0] + ".encode"):
                        os.remove("encode_files/" + filename.split(".")[0] + ".encode")
                    new_file = open("encode_files/" + filename.split(".")[0] + ".encode", "ab")
                    new_file.write(b'******' + EnCrypt(key, b'myfile/0/0/0/0/0') + b'******')
                    new_file.close()
                    for i in range(0, filesize, speed):
                        old_file = f.read(speed)
                        new_file = open("encode_files/" + filename.split(".")[0] + ".encode", "ab")
                        old_file = PadTest(old_file)
                        new_file.write(EnCrypt(key, old_file))
                        new_file.close()
                        if not old_file:
                            break
                        progressbar['value'] = i
                        root.update()  # 更新主窗口，使进度条显示更新
                new_file = open("encode_files/" + filename.split(".")[0] + ".encode", "ab")
                new_file.write(b'//////' + filename.encode())
                new_file.close()
                count=count+1
                progressbar.pack_forget()
        tkinter.messagebox.showinfo("AES文件加密","全部加密完成！共完成"+str(count)+"个文件")
        switch_contralor(True)
        os.popen("explorer encode_files")



def unlock_all_file():
    key = entry.get()
    if key == "":
        tkinter.messagebox.showerror("AES文件加密", "密码不能为空")
    else:
        key = PadKey(key.encode())
        if len(real_filelist) == 0:
            tkinter.messagebox.showerror("AES文件加密", "无可解密文件")
        else:
            if not os.path.exists("decode_files"):
              os.makedirs("decode_files")
            count = 0
            error_file=0
            error_file_state=False
            switch_contralor(False)
            for i in real_filelist:
                filename = i.split("/")[-1]
                if filename.split(".")[-1] != "encode":
                    continue
                try:
                    filesize = os.path.getsize(i)
                except:
                    real_filelist.remove(i)
                    filelist.remove(filename)
                    continue
                    error_file = error_file + 1
                with open(i, "rb") as f:
                    progressbar = ttk.Progressbar(frame5)
                    progressbar['maximum'] = filesize
                    progressbar.pack()
                    for i in range(0, filesize, speed):
                        if i == 0:  # 第一轮循环，校验密码正确性，不能做写入文件的操作
                            fileid = f.read(28)  # 读28位密码校验码，不能写入到文件中，会造成文件错误！
                            fileid = DeCrypt(key, fileid.split(b'******')[1])
                            if fileid != b'myfile/0/0/0/0/0':
                                progressbar.pack_forget()
                                error_file=error_file+1
                                error_file_state=True
                                break
                            elif fileid.split()[0] == b'myfile/0/0/0/0/0':
                                pass  # 继续读，然后开始正式写入
                        old_file = f.read(speed)
                        new_file = open("decode_files/" + filename.split(".")[0] + ".decode", "ab")
                        old_file = PadTest(old_file)
                        old_file_decode = DeCrypt(key, old_file)
                        if b'//////' in old_file:
                            filename_dat = old_file.split(b'//////')[1]
                            new_file.write(DeCrypt(key, old_file.split(b'//////')[0]))# 写入文件名之前的数据，防止文件损坏
                            new_file.close()
                            old_file = f.read(speed)  # 继续往下读，没有就退出，防止有文件名读取不全
                            if old_file:
                                filename_dat = filename_dat + old_file#拓展名的添加
                            else:
                                break
                        new_file.write(old_file_decode)
                        new_file.close()
                        progressbar['value'] = i
                        root.update()  # 更新主窗口，使进度条显示更新
                    if not error_file_state:
                        filename_dat = filename_dat.decode()
                        if os.path.exists("decode_files/" + filename_dat):
                              os.remove("decode_files/" + filename_dat)
                        os.rename("decode_files/" + filename.split(".")[0] + ".decode",
                          "decode_files/" + filename_dat)
                        progressbar.pack_forget()
                        count = count + 1
                    if error_file_state:
                        pass
            tkinter.messagebox.showinfo("AES文件加密", "解密成功！共解密"+str(count)+"个文件，其中"+str(error_file)+"个文件密码错误或文件损坏无法解密。")
            switch_contralor(True)
            os.popen("explorer decode_files")


def unlock_one_file():
    key = entry.get()
    if key == "":
        tkinter.messagebox.showerror("AES文件加密", "密码不能为空")
    else:
        key = PadKey(key.encode())
        if Lstbox1.curselection() == ():
            tkinter.messagebox.showerror("AES文件加密", "未选择任何文件！")
        else:
            try:
                filesize = os.path.getsize(real_filelist[int(Lstbox1.curselection()[0])])
            except:
                tkinter.messagebox.showerror("AES文件加密器", "文件无效！")
                del real_filelist[Lstbox1.curselection()[0]]
                del filelist[Lstbox1.curselection()[0]]
                Lstbox1.delete(Lstbox1.curselection())
                ini()
                return 0
            if not os.path.exists("decode"):
              os.makedirs("decode")
            filename=real_filelist[int(Lstbox1.curselection()[0])].split("/")[-1]
            if filename.split(".")[-1] != 'encode':
                tkinter.messagebox.showerror("AES文件加密器","该文件不是加密文件，无法解密！")
            else:
              switch_contralor(False)
              with open(real_filelist[int(Lstbox1.curselection()[0])], "rb") as f:
                progressbar = ttk.Progressbar(frame5)
                progressbar['maximum'] = filesize
                progressbar.pack()
                for i in range(0, filesize, speed):
                    if i==0:#第一轮循环，校验密码正确性，不能做写入文件的操作
                        fileid = f.read(28)#读28位密码校验码，不能写入到文件中，会造成文件错误！
                        fileid = DeCrypt(key,fileid.split(b'******')[1])
                        if fileid.split()[0] != b'myfile/0/0/0/0/0':
                             tkinter.messagebox.showerror("AES文件加密器", '解压密码错误！')
                             switch_contralor(True)
                             progressbar.pack_forget()
                             return 0#结束函数
                        elif fileid.split()[0] == b'myfile/0/0/0/0/0':
                            pass#进行下一轮循环，这一轮是校验循环，下一个循环才会正式写入
                    old_file = f.read(speed)
                    new_file = open("decode/" + filelist[Lstbox1.curselection()[0]].split(".")[0] + ".decode", "ab")
                    old_file = PadTest(old_file)
                    old_file_decode=DeCrypt(key, old_file)
                    if b'//////' in old_file:
                        filename_dat=old_file.split(b'//////')[1]
                        new_file.write(DeCrypt(key,old_file.split(b'//////')[0]))
                        new_file.close()
                        old_file = f.read(speed)#继续往下读，没有就退出，防止有文件名读取不全
                        if old_file:
                            filename_dat=filename_dat+old_file
                        else:
                            break
                    new_file.write(old_file_decode)
                    new_file.close()
                    progressbar['value'] = i
                    root.update()  # 更新主窗口，使进度条显示更新
              filename_dat=filename_dat.decode()
              if os.path.exists("decode/"+filename_dat):
                  os.remove("decode/"+filename_dat)
              os.rename("decode/"+filelist[Lstbox1.curselection()[0]].split(".")[0]+".decode","decode/"+filename_dat)
              tkinter.messagebox.showinfo("AES文件加密", "解密成功！")
              switch_contralor(True)
              progressbar.pack_forget()
              os.popen("explorer decode")


def deletefile():
    if Lstbox1.curselection() != ():
        del real_filelist[Lstbox1.curselection()[0]]
        del filelist[Lstbox1.curselection()[0]]
        Lstbox1.delete(Lstbox1.curselection())
        ini()



def chosefile():
    filename = tkinter.filedialog.askopenfilename()
    if filename != '':
        real_filelist.append(filename)
        filename=filename.split("/")[-1]
        filelist.append(filename)
        ini()



def encode_speed_sitting():
    global speed
    speed=int(speedvar.get())


def set_key_lenth():
    global AES_KEY_SIZE
    AES_KEY_SIZE = int(keylenth.get())

def switch_contralor(state):
  if state:
      key1["state"] = 'normal'
      key2["state"] = 'normal'
      key3["state"] = 'normal'
  if not state:
      key1["state"] = 'disabled'
      key2["state"] = 'disabled'
      key3["state"] = 'disabled'



def open_file(a):
    if Lstbox1.curselection() != ():
        os.popen(real_filelist[Lstbox1.curselection()[0]])


# 获取路径，打包exe时用的
def getPath(filename):
    bundle_dir = getattr(sys, '_MEIPASS', os.path.abspath(os.path.dirname(__file__)))
    path = os.path.join(bundle_dir, filename)
    return path


root = Tk()
root.title('AES文件加密器V1.2')
real_screen_width = int(root.winfo_screenwidth())
real_screen_height = int(root.winfo_screenheight())
soft_position_x=int(real_screen_width/2-250)
soft_position_y=int(real_screen_height/2-200)
root.geometry('500x300+'+str(soft_position_x)+"+"+str(soft_position_y))
root.resizable(False, False) #横纵均不允许调整
root.iconbitmap(getPath("lock.ico"))

progress = IntVar()
keylenth = IntVar()


frame1 = Frame(root,relief=RAISED)
frame1.place(relx=0.0)

frame2 = Frame(root,relief=GROOVE)
frame2.place(relx=0.69)

frame3 = Frame(root,relief=RAISED)
frame3.place(relx=0.0,rely=0.75)

frame4 = Frame(root,relief=GROOVE)
frame4.place(relx=0.3,rely=0.17)

frame5 = Frame(root,relief=RAISED)
frame5.place(relx=0.32,rely=0.625)


Lstbox1 = Listbox(frame1)
Lstbox1.pack()
Lstbox1.bind("<Double-Button-1>", open_file)


Label(frame2,text="密码：").pack()

entry = Entry(frame2)
entry.pack()

ini()#初始化

Button(frame1,text='选择文件',command=chosefile).pack(fill=X)

Button(frame2,text='全部加密',command=lock_all_file).pack(fill=X)

Button(frame2,text='全部解密',command=unlock_all_file).pack(fill=X)

Button(frame2,text='加密文件',command=lock_one_file).pack(fill=X)

Button(frame2,text='解密文件',command=unlock_one_file).pack(fill=X)

Button(frame2,text='删除',command=deletefile).pack(fill=X)

Button(frame2,text='刷新列表',command=ini).pack(fill=X)




Label(frame4,text="密钥长度").pack()
key1=Radiobutton(frame4,text="128bit",variable=keylenth,value=16,command=set_key_lenth)
key1.pack()
key2=Radiobutton(frame4,text="192bit",variable=keylenth,value=24,command=set_key_lenth)
key2.pack()
key3=Radiobutton(frame4,text="256bit",variable=keylenth,value=32,command=set_key_lenth)
key3.pack()
keylenth.set(16)#默认128位密钥宽度


Label(frame3,text="注意事项：\n1.mp3等媒体文件加密后解密有的播放器会无法播放，换一个播放器即可\n2.解密文件前需预知密钥长度，不然即使密码正确也无法解密，确定密码的话可以一个个尝试\nAES文件加密器是完全免费开源的文件加密程序，不会以各种方式索要他人解密费等").pack()

root.mainloop()
