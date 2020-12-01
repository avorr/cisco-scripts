#!/var/opt/miniconda3/bin/python3.7 
def szf():    
    import re
    import time
    import getpass
    import paramiko
    import seaborn as sns
    import networkx as nx
    import matplotlib.pyplot as plt
    from concurrent.futures import as_completed
    from concurrent.futures import ThreadPoolExecutor
    sns.set()
    G=nx.Graph()    
    
    hostname = input('Hostname/ip: ').strip().encode('latin1').decode('ascii')
    secret = getpass.getpass('Password: ').strip().encode('latin1')
        
    def once_command(command:str, hostname_asr:str, multitreading=False):
        try:
            sshtransport = paramiko.Transport((hostname_asr, 22))
            sshtransport.connect(username = getpass.getuser(), password = secret)
            session = sshtransport.open_channel(kind='session')
            output = []                
            session.exec_command(str(command))
            while True:
                if session.recv_ready():
                    output.append(session.recv(3000).decode('ascii'))
                if session.recv_stderr_ready():
                    output.append(session.recv_stderr(3000).decode('ascii'))
                if session.exit_status_ready():
                    break
            if multitreading == True:
                return [hostname_asr, ''.join(output)]
            else:
                return output
        except paramiko.ssh_exception.AuthenticationException as e:
            print(str(e))
        except paramiko.ssh_exception.SSHException as e:
            print(str(e))
        except EOFError as e:
            print(str(e))
        session.close()
        sshtransport.close()        
                                                
    def output_tcl_asr900(commands:str, hostname_asr:str, one_int=False, info_asr=False):
        sshshell = paramiko.SSHClient()
        sshshell.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sshshell.connect(
            hostname=hostname_asr,
            username=getpass.getuser(),
            password=secret,
            look_for_keys=False,
            allow_agent=False)
        try:
            with sshshell.invoke_shell() as ssh:
                ssh.settimeout(0.1)
                ssh.send('tclsh\n')
                time.sleep(0.2)
                ssh.send(str(commands)+"\n")
                time.sleep(3)
                complete_stdout = ''
                while True:
                    try:
                        if info_asr == True:
                            complete_stdout = ssh.recv(5000).decode('ascii')
                        elif one_int == False and info_asr == False:
                            complete_stdout = ssh.recv(5000).decode('ascii')
                            str_output = ''.join(re.findall(r'.*rate.+' + "\s.*"*14, complete_stdout))
                        else:
                            complete_stdout = ssh.recv(3000).decode('ascii')
                            str_output = ''.join(re.findall(r'.*rate.+' + "\s.*"*5, complete_stdout))                            
                    except paramiko.ssh_exception.socket.timeout:
                        break
            if info_asr == True:            
                return complete_stdout
            else:
                return [hostname_asr, str_output]
        except paramiko.ssh_exception.AuthenticationException as e:
            print(str(e))
        except paramiko.ssh_exception.SSHException as e:
            print(str(e))
        except EOFError as e:
            print(str(e))
                          
    def lookup_bgp_neighbor(bgp_neighbor:list, number_of_agn:int):
        if len(bgp_neighbor) == 2:
            local_agn_neighbor = once_command(" sh cdp neig det | i Dev", bgp_neighbor[number_of_agn])           
            neighborASR900 = re.findall(r'(\S+R+\d{3})\.nw', ''.join(local_agn_neighbor))
              
            for num_of_asr900 in neighborASR900:
                try:
                    agn_ip_neighbor = once_command("sh ip bgp sum | b Nei", num_of_asr900)           
                    find_agn_ip_neighbor = re.findall(r'\d+\.\d+\.\d+\.\d+', ''.join(agn_ip_neighbor))
                    if len(set(bgp_neighbor)&set(find_agn_ip_neighbor)) == 2:              
                        localint = once_command(f'sh cdp nei d | b {num_of_asr900}', bgp_neighbor[number_of_agn])
                        local_int_agn = re.search(r'[TG]+[ei]+\S*', ''.join(localint)).group()#  r'[TG].*\d+\/.+'
                        return [local_int_agn]
                except:
                    print(num_of_asr900, 'unreachable')
                    pass                        
 
        elif len(bgp_neighbor) == 1:
            local_agn_neighbor = once_command(" sh cdp neig det | i Dev", bgp_neighbor[number_of_agn])           
            neighborASR900 = re.findall(r'(\S+R+\d{3})\.nw', ''.join(local_agn_neighbor)) 

            for num_of_asr900 in neighborASR900:
                try:
                    agn_ip_neighbor = once_command("sh ip bgp sum | b Nei", num_of_asr900)           
                    find_agn_ip_neighbor = re.findall(r'\d+\.\d+\.\d+\.\d+', ''.join(agn_ip_neighbor))
                    if  bgp_neighbor == find_agn_ip_neighbor:
                        localint = None               
                        localint = once_command(f'sh cdp nei d | b {num_of_asr900}', bgp_neighbor[number_of_agn])
                        local_int_agn = re.search(r'[TG]+[ei]+\S*', ''.join(localint)).group()#  r'[TG].*\d+\/.+'
                        return [local_int_agn]
                except:
                    print(num_of_asr900, 'unreachable')
                    pass                                       
                      
    def start_script(iphop:str):        
        info_asr = output_tcl_asr900('s ip bgp sum | e (nev|BGP|entr);s ru in lo0 | b add', iphop, False, True)
        ip_bgp_sum = re.findall(r'(\d+\.\d+\.\d+\.\d+)+\s{3}', info_asr)
        bgptime = re.findall(r'\d+[wyd]+\d+[wdh]|\d+:\d+:\d+', info_asr)
        ipasrlo0 = re.search(r'ss+\s+((\d+\.){3}\d+)', info_asr).group(1)
        asr_hostname = re.search(r'(.*)\#', info_asr).group(1)
        
        def topology_mbh(number_of_agn:int, stop_recursion=False, agn_interfaces=None, number_of_int=0):
            sshshell = paramiko.SSHClient()
            sshshell.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            sshshell.connect(
                    hostname = ip_bgp_sum[number_of_agn],
                    username = getpass.getuser(),
                    password = secret,
                    look_for_keys = False,
                    allow_agent = False)
            try:
                    with sshshell.invoke_shell() as ssh:
                            ssh.settimeout(1)
                            time.sleep(1)
                            ssh.send(f' sh mpl ld f {ipasrlo0}/32 | b --\n')
                            time.sleep(1)
                            complete_stdout = ssh.recv(5000).decode('ascii')
                            time.sleep(1)
                            
                            if stop_recursion == True and len(ip_bgp_sum) == 1:                            
                                pass                           
                            else:                                
                                agn_interfaces = re.findall(r'[TG]+[ei]+\S*/+[^.\s]+', complete_stdout)  # [TtGgFfEe]+\w+[0-2/]+[^.]+
                                                                                       
                                if not agn_interfaces:
                                    first_way = once_command(f'sh int desc | i {asr_hostname}', ip_bgp_sum[number_of_agn])               
                                    agn_interfaces = re.findall(r"([TGB]+\S*)\.", ''.join(first_way))                                   
                                if not agn_interfaces:
                                    agn_interfaces = lookup_bgp_neighbor(ip_bgp_sum, number_of_agn)                                         
                            ssh.send(f' sh cdp ne de {agn_interfaces[number_of_int]} | i Dev\n')
                            time.sleep(1.5)
                            ssh.send(f' sh cdp ne {agn_interfaces[number_of_int]} | i Te\n')
                            time.sleep(1.5)
                            output_agn = []
                            output_agn.append(ssh.recv(500).decode('ascii'))
                            nameof_first_agn = re.search(r'([$:]+(.*))#', ''.join(output_agn)).group(2)
                            nexthop = re.search(r'(\S*).nw', ''.join(output_agn)).group(1)
                            findintCSG = re.findall(r'[TG]+[ei]+\S*', ''.join(output_agn))                            
            except paramiko.ssh_exception.AuthenticationException as e:
                    print(str(e))
            except paramiko.ssh_exception.SSHException as e:
                    print(str(e))
            except EOFError as e:
                    print(str(e))
          
            ring_csg = []; ringint = []; ringint2 = []
            ring_csg.append(nameof_first_agn); ring_csg.append(nexthop)
            ringint.append(findintCSG[-1]); ringint2.append(agn_interfaces[number_of_int])
            
            sep_vl = lambda x: x.replace('Vl', 'Vl ') if 'Vl' in x else (x.replace('BDI', 'BD ') if 'BDI' in x else x.replace('BD', 'BD '))
            
            if len(ip_bgp_sum) == 2:                
                while True:
                    cdp_neighbors = once_command('s cdp n | b De', nexthop)
                    nexthopall = re.findall(r'(.*)\.nw.', ''.join(cdp_neighbors))
                                        
                    if len(nexthopall) > 2:

                        find_hop_int = once_command(f's mpl for {ip_bgp_sum[1]} | i (BDI|BD|Vl)', nexthop)
                        find_bd = re.findall(r'BD\S+|Vl\S+', ''.join(find_hop_int))
                        find_hop_int = once_command(f's mac-a {sep_vl(find_bd[0])} | i (Te|Gi)', nexthop)
                        find_phy_int = re.search(r'[TG][ei]+(\d/){1,2}\d+', ''.join(find_hop_int)).group()
                        cdp_neighbors = once_command(f's cdp n {find_phy_int} | b De', nexthop)                               
                        nexthopall = re.findall(r'(.*)\.nw.', ''.join(cdp_neighbors))
                    nexthop = ''.join(set(nexthopall)-set(ring_csg))
                                                                
                    if len(nexthop) == 0 and stop_recursion == False: #and ring_csg[0] not in nexthopall:                    
                        ring_csg_first_part.append(ring_csg); ring_csg_first_part.append(ringint); ring_csg_first_part.append(ringint2)
                        global ring_csg_break
                        ring_csg_break = topology_mbh(1, True)                    
                        break
                        
                    elif ring_csg[0] in nexthopall and len(nexthop) == 0:
                        ring_csg.append(ring_csg[0]+'two')
                        return [ring_csg, ringint, ringint2]
                        
                    elif len(nexthop) == 0 and stop_recursion == True:                                                          
                        return [ring_csg, ringint, ringint2]
                                                             
                    reg_exp = rf'{nexthop}' + r".+\s+([TG]+\w+\s+\S*).*([TH].*)" # r'.+\s+([T]+\w+\s+\d+/+\d+(/+\d+)?).*([T].+)'
                    intring2 = re.search(reg_exp, ''.join(cdp_neighbors)).group(1)
                    intring = re.search(reg_exp, ''.join(cdp_neighbors)).group(2)
                    ring_csg.append(nexthop); ringint.append(intring[0:-1]); ringint2.append(intring2)
                                        
                    if re.search(r'ASR9\d{3}', ring_csg[-1]):
                        return [ring_csg, ringint, ringint2]
                    
            elif len(ip_bgp_sum) == 1:                                
                while True:
                    cdp_neighbors = None    
                    cdp_neighbors = once_command('s cdp n | b De', nexthop)    
                    nexthopall = re.findall(r'(.*)\.nw.', ''.join(cdp_neighbors))                    
                    nexthop = ''.join(set(nexthopall)-set(ring_csg))
                    
                    if len(nexthop) == 0 and stop_recursion == False and ring_csg[0] not in nexthopall:                    
                        ring_csg_first_part.append(ring_csg); ring_csg_first_part.append(ringint); ring_csg_first_part.append(ringint2)                        
                        check_int = once_command(f'sh int desc | i {asr_hostname}', ip_bgp_sum[number_of_agn])               
                        agn_int_desc = re.findall(r"([TGB]+\S*)\.", ''.join(check_int))
                        
                        if len(agn_int_desc) == 2 and len(agn_interfaces) == 1: 
                            two_agn_int = list((set(agn_int_desc)-set(agn_interfaces)))
                            global once_agn_break
                            once_agn_break = topology_mbh(0, True, two_agn_int, 0)
                            break     
                        
                    elif ring_csg[0] in nexthopall and len(nexthop) == 0:
                        ring_csg.append(ring_csg[0])
                        return [ring_csg, ringint, ringint2]
                        
                    elif len(nexthop) == 0 and stop_recursion == True:                                                          
                        return [ring_csg, ringint, ringint2]
                                                             
                    reg_exp = rf'{nexthop}' + r".+\s+([TG]+\w+\s+\S*).*([TH].*)" # r'.+\s+([T]+\w+\s+\d+/+\d+(/+\d+)?).*([T].+)'
                    intring2 = re.search(reg_exp, ''.join(cdp_neighbors)).group(1)
                    intring = re.search(reg_exp, ''.join(cdp_neighbors)).group(2)
                    ring_csg.append(nexthop); ringint.append(intring[0:-1]); ringint2.append(intring2)
                    
                    if re.search(r'ASR9\d{3}', searchasr):
                        return [ring_csg, ringint, ringint2]
                        
        ring_csg_first_part = []
        outputmbh = topology_mbh(0)
        
        def build_graphs(ring_csg:list, ringint:list, ringint2:list):            
            if len(ring_csg)%2 == 0 and ring_csg[0] != ring_csg[-1]:
                for asr_node,asr_pos in zip(ring_csg, range(len(ring_csg)//2)):
                    if ring_csg.index(asr_node) < len(ring_csg)//2:
                        G.add_node(asr_node, pos=(asr_pos,((len(ring_csg)//2)**2-asr_pos**2)**0.5))
    
                for asr_node,asr_pos in zip(ring_csg[::-1], range(len(ring_csg)//2)):
                    if ring_csg.index(asr_node) >= len(ring_csg)//2:
                        G.add_node(asr_node, pos=(asr_pos,-((len(ring_csg)//2)**2-asr_pos**2)**0.5))
    
                for asr1,asr2,int1,int2 in zip(range(len(ring_csg)), range(1, len(ring_csg)), ringint, ringint2):
                    if asr1 <= len(ringint)//2:
                        G.add_edge(ring_csg[asr1], ring_csg[asr2], interfaces=int2+'-'+int1, relation='neighbor')
                    else:
                        G.add_edge(ring_csg[asr1], ring_csg[asr2], interfaces=int1+'-'+int2, relation='neighbor')
            
            elif len(ring_csg)%2 != 0 and ring_csg[0] != ring_csg[-1]:
                for asr_node,asr_pos in zip(ring_csg, range(len(ring_csg)//2+1)):
                    if ring_csg.index(asr_node) < len(ring_csg)//2:
                        G.add_node(asr_node, pos=(asr_pos,((len(ring_csg)//2)**2-asr_pos**2)**0.5))
    
                for asr_node,asr_pos in zip(ring_csg[::-1], range(len(ring_csg)//2+1)):
                    if ring_csg.index(asr_node) >= len(ring_csg)//2:
                        G.add_node(asr_node, pos=(asr_pos,-((len(ring_csg)//2)**2-asr_pos**2)**0.5))
    
                for asr1,asr2,int1,int2 in zip(range(len(ring_csg)), range(1, len(ring_csg)), ringint, ringint2):
                    G.add_edge(ring_csg[asr1], ring_csg[asr2], interfaces=int1+'-'+int2, relation='neighbor')
    
                for asr1,asr2,int1,int2 in zip(range(len(ring_csg)), range(1, len(ring_csg)), ringint, ringint2):
                    if asr1 < len(ringint)//2:
                        G.add_edge(ring_csg[asr1], ring_csg[asr2], interfaces=int2+'-'+int1, relation='neighbor')
                    else:
                        G.add_edge(ring_csg[asr1], ring_csg[asr2], interfaces=int1+'-'+int2, relation='neighbor')
        
        def draw_graphs():
            pos = nx.get_node_attributes(G, 'pos')
            labels = nx.get_edge_attributes(G, 'interfaces')
            relation = nx.get_edge_attributes(G, 'relation')
            ref = {'neighbor': 'green', 'linkdown': 'red', 'ibgp': 'red'}
            nx.draw_networkx(G, pos, edge_color=[ref[x] for x in relation.values()])
            nx.draw_networkx_edge_labels(G,pos,edge_labels=labels)
                                                           
        if outputmbh == None and len(ip_bgp_sum) == 2:
            ring_csg = ring_csg_first_part[0] + ring_csg_break[0][::-1]
            ring_csg_first_part[1].append(''); ring_csg_break[1].append('')
            ring_csg = ring_csg_first_part[0] + ring_csg_break[0][::-1]
            ringint = ring_csg_first_part[1] + ring_csg_break[2][::-1]
            ringint2 = ring_csg_first_part[2] + ring_csg_break[1][::-1]
            
            if __name__ != "__main__":
                build_graphs(ring_csg, ringint, ringint2)
                G.add_edge(ring_csg_first_part[0][-1], ring_csg_break[0][-1], interfaces='Break', relation='linkdown')
                    
                try:
                    G.add_edge(ring_csg[ring_csg.index(asr_hostname)], ring_csg[0],interfaces=bgptime[0], relation='ibgp')
                    G.add_edge(ring_csg[ring_csg.index(asr_hostname)], ring_csg[-1],interfaces=bgptime[1], relation='ibgp')
                except:
                    pass                        
                draw_graphs()            
            
            with ThreadPoolExecutor(max_workers = len(ring_csg)) as executor:
                ringint.insert(0, ''); ringint2.append('')
                running_functions = []; ring_output = list(range(len(ring_csg)));
                for asr, asrint, asrint2 in zip(ring_csg, ringint, ringint2):                    
                    if asr == ring_csg[0] or asr == ring_csg[-1]:
                        running_functions.append(executor.submit(once_command, f'sh int {asrint} {asrint2} | b Last', asr, True))
                    else:
                        command_tcl =  rf'sh int {asrint} | i (bits|errors);sh int {asrint} tra | b ---;puts \n\n{asrint2.replace(" ","")};sh int {asrint2} | i (bits|errors);sh int {asrint2} tra | b ---'
                        com_tcl_one_int = rf'sh int {asrint}{asrint2} | i (bits|errors);sh int {asrint}{asrint2} tra | b ---'
                        if any(asrint) == False or any(asrint2) == False: 
                            running_functions.append(executor.submit(output_tcl_asr900, com_tcl_one_int, asr, True))
                        else:
                            running_functions.append(executor.submit(output_tcl_asr900, command_tcl, asr))
      
                for function in as_completed(running_functions):         
                    asr_output = function.result()        
                    ring_output[ring_csg.index(asr_output[0])] = asr_output[1]
        
                for host,intasr,result in zip(ring_csg, ringint, ring_output):
                    print(str(ring_csg.index(host) + 1) + ')', f'\033[34m{host}\033[0m')
                    print(intasr)
                    print(result + '\n')
                                                                              
        elif not ring_csg_first_part:            
            ring_csg = outputmbh[0]; ringint = outputmbh[1]; ringint2 = outputmbh[2]
            if __name__ != "__main__":   
                build_graphs(ring_csg, ringint, ringint2)                                    
                try:
                    G.add_edge(ring_csg[ring_csg.index(asr_hostname)], ring_csg[0],interfaces=bgptime[0], relation='ibgp')
                    G.add_edge(ring_csg[ring_csg.index(asr_hostname)], ring_csg[-1],interfaces=bgptime[1], relation='ibgp')
                except:
                    pass            
                draw_graphs()
               
            with ThreadPoolExecutor(max_workers=len(ring_csg)) as executor:
                ringint.insert(0, ''); ringint2.append('')
                running_functions = []; ring_output=list(range(len(ring_csg)));
                for asr, asrint, asrint2 in zip(ring_csg, ringint, ringint2):
                
                    if asr == ring_csg[0] or asr == ring_csg[-1]:
                        running_functions.append(executor.submit(once_command, f'sh int {asrint} {asrint2} | b Last', asr, True))
                    else:
                        command_tcl =  rf'sh int {asrint} | i (bits|errors);sh int {asrint} tra | b ---;puts \n\n{asrint2.replace(" ","")};sh int {asrint2} | i (bits|errors);sh int {asrint2} tra | b ---'
                        running_functions.append(executor.submit(output_tcl_asr900, command_tcl, asr))
                
                for function in as_completed(running_functions):         
                    asr_output = function.result()        
                    ring_output[ring_csg.index(asr_output[0])] = asr_output[1]
        
                for host,intasr,result in zip(ring_csg, ringint, ring_output):
                    print(str(ring_csg.index(host) + 1) + ')', f'\033[34m{host}\033[0m')
                    if ring_csg.index(host) == 0:
                        print(ringint2[0])
                    else:
                        print(intasr)
                    print(result + '\n') # print(''.join(result).replace('Ten0/0/12', "\033[42mTen0/0/12\033[0m"))
               
    sshshellhostname = paramiko.SSHClient()
    sshshellhostname.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sshshellhostname.connect(
        hostname=hostname,
        username=getpass.getuser(),
        password=secret,
        look_for_keys=False,
        allow_agent=False)
    try:
        sshhost = sshshellhostname.invoke_shell()
        sshhost.settimeout(0.1)
        sshhost.send(' sh run int lo0\n')
        time.sleep(1.5)
        first_output = []
        first_output.append(sshhost.recv(300).decode('ascii'))
    except paramiko.ssh_exception.AuthenticationException as e:
        print(str(e))
    except paramiko.ssh_exception.SSHException as e:
        print(str(e))
    except EOFError as e:
        print(str(e))

    searchasr = re.search(r'(.*)#', ''.join(first_output)).group()
    searchiplo0 = re.search(r'(\d+\.){3}\d+', ''.join(first_output)).group()
        
    if re.search(r'ASR9\d{3}', searchasr):
        neighbor_asr9k = None	
        neighbor_asr9k = once_command("sh cdp neig det | i Dev", searchiplo0)
        all_cdp_asr900 = re.findall(r'(\S*R\d{3})\.nw', ''.join(neighbor_asr9k))
        asr_900 = []

        for num_of_asr, asr in enumerate(all_cdp_asr900, 1):
            print(f'{num_of_asr}) {asr}')
            asr_900.append(asr)
        asr_900_number = input('№ of router: ')
        start_script(asr_900[int(asr_900_number)-1]) 
    else:        
        start_script(searchiplo0)                
if __name__ == "__main__":
    szf()
    exit()