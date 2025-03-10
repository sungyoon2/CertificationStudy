# UNIX / Linux 서버보안
---
시스템 보안
---
> passwd(/etc/passwd) 파일<br>
```
<파일형식>
[user_account]:[user_password]:[user_ID]:[group_ID]:[comment]:[home_directory]:[login_shell]
- password에 x의 표시는 shadow 패스워드를 사용한다는 의미
**login이 불필요한 계정에 대해서는(시스템 및 애플리케이션 계정) 로그인을 금지하도록 설정 -> 공격자에 의한 불법적인 시스템 접근에 악용되지 않도록
    => 해당 계정 로그인쉘을 /sbin/nologin 또는 /bin/false로 설정
```
> shadow(/etc/shadow) 파일<br>
- 패스워드를 암호화해 보관하는 곳, root만 읽을 수 있도록 기본적인 접근권한이 설정
```
<파일 형식>
[user_account]:[encrypted_password]:[last_change]:[minlife]:[maxlife]:[warn]:[inactivel]:[expire]
  (권장 설정)
    - minlife : 1일 또는 1주로 설정
    - maxlife : 90일(12주)로 설정
    *inactive의 차이 : (리눅스) 패스워드가 만료된 이후 계정이 잠기기까지 비활성일수
                       (유닉스) 마지막 로그인이후 해당 비활성 일수 동안 로그인하지 않으면 계정을 잠근다의 의미
<encryted_password 필드 구성>
$ID$Salt$encryted_password
  - Salt를 통해 레인보우 테이블 공격에 효과적으로 대응가능
<encrypted_password의 기호>
  (리눅스)
      * : 패스워드가 잠긴 상태로 패스워드 로그인은 불가능하지만, 별도의 인증방식을 사용하여(ex.SSH 인증키) 로그인은 가능
      !! : 패스워드가 잠긴 상태로 모든 로그인이 불가능, 기본적으로 사용자 계정을 생성하고 패스워드가 설정되지 않은 상태
      빈값 : 패스워드가 설정되지 않은 상태, 패스워드가 설정되어 있지 않으면 패스워드 없이 로그인할 수 있음
  (유닉스)
      NP : 로그인 할 수 없는 계정 -> 시스템 및 애플리케이션 계정용도로 주로 사용
      *LK* : LOCK의 의미로 패스워드가 잠긴상태로 로그인 불가
      빈값 : 패스워드가 설정되지 않음 -> 로그인시 패스워드 설정 과정이 진행됨
```
> password관련 정책<br>
```
- 패스워드 잠금 설정 : passwd -l 계정명
- 패스워드 잠금 해제 : passwd -u 계정명
- pwconv : 사용자 계정 패스워드 저장정책을 shadow 패스워드 정책으로 변경하는 명령어
- pwunconv : 사용자 계정 패스워드 저장정책을 일반 패스워드 정책으로 변경하는 명령어
```
> 자원에 대한 접근권한의 구분<br>
- RUID(Real User ID) : 프로세스를 실행시킨 사용자의 UID
- RGID(Real Group ID) : 프로세스를 실행시킨 사용자의 GID
- EUID(Effective User ID) : 프로세스가 실행 중인 동안만 부여되는 UID로 자원 접근권한을 판단하기 위한 UID로 사용
- EGID(Effective Group ID) : 프로세스가 실행 중인 동안만 부여되는 GID로 자원 접근권한을 판단하기 위한 GID로 사용
> ROOT소유 SUID, SGID 실행파일 주기적 검사<br>
- root권한이 필요없는 프로그램에 소유주가 root로 되어있으면서 setuid가 설정된 경우 보안상매우 취약하기에 주기적인 검사가 필요
```
< 검사 명령어 >
find / -user root -type f \( -perm -4000 -o -perm -2000 \) -exec ls -al {} \;
: 소유자가 root이고 파일 유형이 일반(실행)파일이고 SUID 또는 SGID가 설정된 파일 정보를 상세 출력
< 제거 명령어 >
chmod -s 실행파일명 => -s 옵션을 사용해 suid, sgid권한을 모두 제거
```
---
네트워크 보안
---
> 보안 쉘[SSH]
