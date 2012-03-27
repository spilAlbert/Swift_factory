-module(swift_factory).
-compile(export_all).


start_global(User,Pass) ->
			global:register_name(?MODULE, Pid=spawn(?MODULE,init,[User,Pass])),
			Pid ! {self(),gimme_da_token},
			receive
	                	{error,Msg} -> {error,Msg};
	                	{_SUrl,_Auth} -> ok
			after 5000 ->
	        	        {error,timeout}
	                end.

start() ->	{error, "No user and/or password provided"}.

start(User,Pass) -> 
		Launched = is_pid(erlang:whereis(swift_factory)),
		if Launched == true -> 	erlang:unregister(?MODULE),
				      	register(?MODULE, Pid=spawn(?MODULE,init,[User,Pass]));
		   Launched == false -> register(?MODULE, Pid=spawn(?MODULE,init,[User,Pass]))
		end,
		Pid ! {self(),gimme_da_token},
	   	receive 
			{error,Msg} -> {error,Msg};
			{_SUrl,_Auth} -> ok
	   	after 5000 ->
			{error,timeout}
	   	end.

stop() ->
	   erlang:whereis(?MODULE) ! shutdown,
	   ok.

get_token() ->
	Pid =  case erlang:whereis(?MODULE) of 
			undefined -> start();
			SPid -> SPid
		end,

	Pid ! {self(),gimme_da_token},
	receive 
		{SUrl,AuthToken} -> {SUrl,AuthToken}
	after 2000 ->
		{error,timeout}
	end.

upload_file(Path,Location) ->
        Pid =  case erlang:whereis(?MODULE) of
			undefined -> start();
                        SPid -> SPid
                end,
	Pid ! {self(),uploadfile, Location ,Path},
	receive
		{ok,{201,Final_Path}} -> {ok,Final_Path};
		{ok,{_,Msg}} -> {warning,Msg};
		{error,_Msg} -> {error,_Msg}
	after 2000 ->
		{error,timeout}
        end.

make_public(Location) ->
        Pid =  case erlang:whereis(?MODULE) of
			undefined -> start();
                	 SPid -> SPid
                end,
	Pid ! {self(),make_public,Location,{"X-Container-Read"," .r:*"}},
	receive
		{ok} -> {ok};
		{error,Message} -> {error,Message}
	after 2000 ->
		{error,timeout}
	end.

change_permissions(Location,ACL) ->
	Pid = case erlang:whereis(?MODULE) of
                        undefined -> start();
                         SPid -> SPid
              end,
	Pid ! {self(),change_permissions,Location,ACL},
	receive
		{ok} -> {ok};
		{error,Message} -> {error,Message}
        after 2000 ->
                {error,timeout}
        end.

list_content(Location) ->
        Pid = case erlang:whereis(?MODULE) of
                        undefined -> start();
                         SPid -> SPid
              end,
	Pid ! {self(),list_content,Location},
        receive
                {ok,Content} -> {ok,Content};
                {error,Message} -> {error,Message}
        after 2000 ->
                {error,timeout}
        end.



loop(User,Pass,Token,Url) ->
	receive 
		{Client,gimme_da_token} ->
			TokenSize = tuple_size(Token),
			if TokenSize == 0 ->
				Headers = [{"X-Storage-User",User},{"X-Storage-Pass",Pass}],
                        	case httpc:request(get, { "http://files-stg.spilcloud.com/auth/v1.0",Headers},[],[]) of
					{ok,{{_,200,_}, ReturnHeaders, _Body}} ->
			                        {value,AuthToken} = lists:keysearch("x-auth-token",1,ReturnHeaders),
        			                {value,{_,SUrl}} = lists:keysearch("x-storage-url",1,ReturnHeaders),
						Client ! {SUrl,AuthToken},
						loop(User,Pass,AuthToken,SUrl);

					{ok,{{_,401,_},_,_}} ->
						Client ! {error,"Not Authorized"},
						loop(User,Pass,Token,Url);
					_ ->
						Client ! {error, "Unexpected response from the SHP service"},
						loop(User,Pass,Token,Url)
				end;

			true -> 
				case httpc:request(get,{Url,[Token]},[],[]) of
                                	{ok,{{_,Code,_},_,_}} when Code > 199 , Code < 299 ->	
							Client ! {Url,Token},
							loop(User,Pass,Token,Url);
	                                {ok,{{_,401,_},_,_}}  ->
							Headers = [{"X-Storage-User",User},{"X-Storage-Pass",Pass}],
			                                {ok,{{_,200,_}, ReturnHeaders, _Body}} = httpc:request(get, { "http://files-stg.spilcloud.com/auth/v1.0",Headers},[],[]),
	                       			        {value,_AuthToken} = lists:keysearch("x-auth-token",1,ReturnHeaders),
			                                {value,{_,_SUrl}} = lists:keysearch("x-storage-url",1,ReturnHeaders),
			                                Client ! {_SUrl,_AuthToken},
	                       			        loop(User,Pass,_AuthToken,_SUrl);
	                                {ok,{{_,_Code,_},_,_}} ->
                                                        Client ! {error,_Code},
							loop(User,Pass,Token,Url);
					_ ->
						Client ! {error, "Could not contact the server"},
						loop(User,Pass,Token,Url)
				end
                        end;

		{Client, uploadfile, Location ,Path} ->
			%check Token
			TokenSize = tuple_size(Token),
		        if TokenSize == 0 ->
				Client ! {error, "no token available"};
			true ->	
				{ok,RawData} = file:read_file(Path),
				[Filename|_] = lists:reverse(string:tokens(Path,"/")),
				Data = binary_to_list(RawData),
				Boundary = "------------a450glvjfEoqerAc1p431paQlfDac152cadAD" ++ integer_to_list(random:uniform(9)) ++ integer_to_list(random:uniform(9)),
				ContentType = lists:concat(["multipart/form-data; boundary=",Boundary]),
				Body = format_multipart_formdata(Boundary,[],[{file,Filename,Data}]),
				Headers = [Token] ++ [{"Content-Length", integer_to_list(length(Body))}],
				case  httpc:request(put,{Url++Location++"/"++Filename,Headers,ContentType,Data},[],[]) of
					{ok,{{_,Code,_},_,_}} when Code == 201 ->
						Client ! {ok,{Code,Url++Location++"/"++Filename}},
						loop(User,Pass,Token,Url);
					{ok,{{_,Code,Msg},_,_}} when Code > 199 , Code < 299 ->
						Client ! {ok,{Code,Msg}},
						loop(User,Pass,Token,Url);
					{ok,{{_,401,_},_,_}}  ->
						Client ! {error,"Not authorized!"},
						loop(User,Pass,Token,Url);
					{ok,{{_,Code,_},_,_}}  ->
						Client ! {error,Code},
						loop(User,Pass,Token,Url);
					_ ->
						Client ! {error, "Could not contact the server"},
	                                       loop(User,Pass,Token,Url)
				end
			end,
			loop(User,Pass,Token,Url);

		{Client,change_permissions, Location, ACL} ->
                        TokenSize = tuple_size(Token),
                        if TokenSize == 0 ->
                                Client ! {error, "no token available"};
                        true ->
				Headers = [Token] ++ [ACL],
				case httpc:request(post,{Url++Location,Headers,[],[]},[],[]) of
					{ok,{{_,Code,_},_,_}} when Code > 199 , Code < 299 ->
						Client ! {ok};
					_ ->
						Client ! {error, "Could not contact the server"}
				end
			end,
			loop(User,Pass,Token,Url);

		{Client, list_content, Location} ->
			TokenSize = tuple_size(Token),
                        if TokenSize == 0 ->
                                Client ! {error, "no token available"};
                        true ->
				case httpc:request(get,{Url++Location,[Token]},[],[]) of
					{ok,{{_,200,_},_,Response}} -> 	Client ! {ok,string:tokens(Response,"\n")};
					{ok,{{_,404,_},_,Response}} -> 	Client ! {error,Response};
					_ ->	Client ! {error,"Could not contact the server"}
				end
			end,
			loop(User,Pass,Token,Url); 


		{Client,_} ->
			Client ! {error,"what?"},
			loop(User,Pass,Token,Url);
		
		shutdown -> exit(shutdown)
			
	end.


init(User,Pass) ->
	% Here we should load the configuration from a config file
	inets:start(),
	loop(User,Pass,{},"").

	


% Internal functions

%% @doc encode fields and file for HTTP post multipart/form-data.
%% @reference Inspired by <a href="http://code.activestate.com/recipes/146306/">Python implementation</a>.
format_multipart_formdata(Boundary, Fields, Files) ->
    FieldParts = lists:map(fun({FieldName, FieldContent}) ->
                                   [lists:concat(["--", Boundary]),
                                    lists:concat(["Content-Disposition: form-data; name=\"",atom_to_list(FieldName),"\""]),
                                    "",
                                    FieldContent]
                           end, Fields),
    FieldParts2 = lists:append(FieldParts),
    FileParts = lists:map(fun({FieldName, FileName, FileContent}) ->
                                  [lists:concat(["--", Boundary]),
                                   lists:concat(["Content-Disposition: form-data; name=\"",atom_to_list(FieldName),"\"; filename=\"",FileName,"\""]),
                                   lists:concat(["Content-Type: ", "application/octet-stream"]),
                                   "",
                                   FileContent]
                          end, Files),
    FileParts2 = lists:append(FileParts),
    EndingParts = [lists:concat(["--", Boundary, "--"]), ""],
    Parts = lists:append([FieldParts2, FileParts2, EndingParts]),
    string:join(Parts, "\r\n").
