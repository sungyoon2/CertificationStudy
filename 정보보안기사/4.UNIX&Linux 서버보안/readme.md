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
> 보안 쉘[SSH]<br>
- 기존의 rsh, rlogin, Talnet, FTP 등의 평문 송수신의 취약점(스니핑, 재전송 공격)을 대체하기 위해 설계, 디폴트로 22/TCP포트를 사용
- 여기서 rsh, rlogin은 IP Spoofing의 취약점도 가짐(신뢰관계의 취약점)
> 슈퍼서버[inetd 데몬]<br>
- 효율적인 서버자원의 활용측면에서 공토적인 부분을 처리하는 슈퍼데몬을 만들어 클라이언트의 요청은 슈퍼데몬이 모두 처리하고 개별 서비스를 호출해 주는 방식
```
<inetd 데몬>
- N개의 개별 서버를 하나로 통합하여 클라이언트로부터 서비스 요청이 올때마다 해당 서비스에 관련된 실행모듈(FTP,Talnet,SSH등)을 실행해줌
- 최초 실행시 /etc/inetd.conf 파일을 참조 -> inetd으로 서비스할 프로그램의 특징을 /etc/inetd.conf파일에 정의해야함
- TCP Wrapper 서비스(tcpd)와 연동하여 서비스별 호스트접근제어를 수행가능(secure os(커널위에 올림)를 많이 사용)
- 리눅스시스템은 xinetd 데몬을 주로 사용, 보안과 자원 관리등을 향상시킨것

<inetd.conf구조>
[서비스명] [소켓타입] [프로토콜] [플래그] [사용할 사용자 계정] [실행 경로명] [실행 인수]
- [소켓타입] : TCP기반 서비스는 stream, UDP기반 서비스는 datagram
- [플래그] : 요청받은 직후 즉시 다음 서비스요청 처리시 -> nowait / 요청처리가 완료될 때까지 대기하였다가 다음 요청을 처리 -> wait

<불필요하고 보안상 취약한 서비스> - 비활성화(주석처리)나 삭제
- DoS공격에 취약한 Simple TCP 서비스 : echo(7/TCP), discard(9/TCP), daytime(13/TCP), chargen(19/TCP)등
- r 계열 서비스 : 인증 없이 관리자의 원격 접속을 가능하게하는 명령어, 보안상 매우 취약
- 불필요한 rpc(remote procedure call) 서비스 : 분산환경에서 서버 응용 프로그램에 접근하여 작업 호출을 할 수 있는 서비스, 버퍼오버플로우 등 다수 취약점이 존재
- 기타 : finger, tftp, talk등등
**inetd.conf 설정을 적용하기위해서 inetd 서비스를 재시작한다.
```
> 접근 통제(TCP Wrapper)<br>
- 서비스별 접근통제
- 사용시 실행경로에 /usr/sbin/tcpd를 명시
```
<접근순서>
1. hosts.allow
2. hosts.deny
3. default로 모든 접근을 허용
<형식>
[service_list] : [client_list] [: shell_command]
- shell_command : twist -> 명령의 결과를 클라이언트에게 전송   // spawn -> 명령의 결과를 클라이언트에 전송하지 않음
```
> xinetd 슈퍼데몬<br>
- TCP Wrapper의 기능 뿐만아니라  자체적으로 다양한 서비스별 접근제어 기능을 제공
```
< 설정 파일 형식(일반설정)>
- disable : 서비스의 실행 여부를 결정(yes : 실행안함 , no : 실행함)

< 설정 파일 형식(접근제어 관련)>
- only_from : 접근을 허용할 특정 ip 주소 또는 ip 주소대역을 설정 -> 공백을 구분자/ip주소대역은 CIDR 표기를 사용
- no_access : 접근을 차단할 특정 ip 주소 또는 ip 주소대역을 설정
- access_times : 접근을 허용할 시간 범위를 설정, 공백을 구분자
- cps : connection per second -> 초당 연결개수를 제한하기 위한 초당 최대 연결개수를 설정, 2개의 인수를 지정-> 첫 번째 인수는 초당 최대 연결개수를 의미, 두 번째 인수는 초당 최대연결개수 초과시 연결을 제한하는 시간을 의미
- instances : 동시에 서비스할 수 있는 서버(서비스 프로세스) 개수를 제한하기 위한 최대 서버 개수를 설정
- per_source : 출발지 ip를 기준으로 서비스 연결개수를 제한하기 위한 출발지 ip별 최대 연결 개수를 설정

```

