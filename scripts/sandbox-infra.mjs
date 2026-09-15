import {readFile,writeFile} from 'node:fs/promises';
const {browserName,policyKey}=JSON.parse(await readFile('infra/sandbox-artifacts.json','utf8'));
const ref=n=>({Ref:n}),sub=s=>({'Fn::Sub':s}),att=(n,k='Arn')=>({'Fn::GetAtt':[n,k]});
const allow=(Action,Resource)=>({Effect:'Allow',Action,Resource});
const assume=service=>({Version:'2012-10-17',Statement:[{Effect:'Allow',Principal:{Service:service},Action:'sts:AssumeRole'}]});
const policy=(name,statements)=>({PolicyName:name,PolicyDocument:{Version:'2012-10-17',Statement:statements}});
const ready=(Type,Properties,extra={})=>({Type,Condition:'Ready',...extra,Properties});
const t={AWSTemplateFormatVersion:'2010-09-09',Description:'Smithey Lab public CAPTCHA inspector. Five starts per UTC day, 100 per month, one active browser, automatic 60-second expiry.',Parameters:{CodeKey:{Type:'String',Default:'',Description:'Content-addressed private Lambda zip key. Empty bootstraps only the asset bucket.'},Enabled:{Type:'String',Default:'false',AllowedValues:['true','false'],Description:'Kill switch for new sessions. Existing sessions still expire automatically.'}},Conditions:{Ready:{'Fn::Not':[{'Fn::Equals':[ref('CodeKey'),'']}] }},Resources:{},Outputs:{}};
t.Parameters.AllowedOrigins={Type:'CommaDelimitedList',Default:'https://example.com',Description:'Explicit HTTPS frontend origins. Replace before deployment.'};
const r=t.Resources;
r.Assets={Type:'AWS::S3::Bucket',DeletionPolicy:'Retain',UpdateReplacePolicy:'Retain',Properties:{PublicAccessBlockConfiguration:{BlockPublicAcls:true,BlockPublicPolicy:true,IgnorePublicAcls:true,RestrictPublicBuckets:true},BucketEncryption:{ServerSideEncryptionConfiguration:[{ServerSideEncryptionByDefault:{SSEAlgorithm:'AES256'}}]},OwnershipControls:{Rules:[{ObjectOwnership:'BucketOwnerEnforced'}]}}};
r.AssetsPolicy={Type:'AWS::S3::BucketPolicy',Properties:{Bucket:ref('Assets'),PolicyDocument:{Version:'2012-10-17',Statement:[{Effect:'Deny',Principal:'*',Action:'s3:*',Resource:[att('Assets','Arn'),sub('${Assets.Arn}/*')],Condition:{Bool:{'aws:SecureTransport':false}}}]}}};
r.RateTable=ready('AWS::DynamoDB::Table',{BillingMode:'PAY_PER_REQUEST',AttributeDefinitions:[{AttributeName:'id',AttributeType:'S'}],KeySchema:[{AttributeName:'id',KeyType:'HASH'}],TimeToLiveSpecification:{AttributeName:'expires',Enabled:true},SSESpecification:{SSEEnabled:true}},{DeletionPolicy:'Retain',UpdateReplacePolicy:'Retain'});
const browserTrust=assume('bedrock-agentcore.amazonaws.com');browserTrust.Statement[0].Condition={StringEquals:{'aws:SourceAccount':ref('AWS::AccountId')},ArnLike:{'aws:SourceArn':sub('arn:${AWS::Partition}:bedrock-agentcore:${AWS::Region}:${AWS::AccountId}:*')}};
r.BrowserRole=ready('AWS::IAM::Role',{AssumeRolePolicyDocument:browserTrust,Policies:[policy('ReadOnlyBrowserPolicy',[allow(['s3:GetObject','s3:GetObjectVersion'],sub('${Assets.Arn}/'+policyKey))])]});
r.Browser=ready('AWS::BedrockAgentCore::BrowserCustom',{Name:browserName,NetworkConfiguration:{NetworkMode:'PUBLIC'},RecordingConfig:{Enabled:false},BrowserSigning:{Enabled:false},ExecutionRoleArn:att('BrowserRole'),EnterprisePolicies:[{Location:{Bucket:ref('Assets'),Prefix:policyKey},Type:'MANAGED'}]});
r.ControllerRole=ready('AWS::IAM::Role',{AssumeRolePolicyDocument:assume('lambda.amazonaws.com'),Policies:[policy('SandboxOnly',[
  {...allow(['dynamodb:GetItem','dynamodb:UpdateItem','dynamodb:PutItem'],att('RateTable')),Condition:{'ForAllValues:StringLike':{'dynamodb:LeadingKeys':['sandbox:*']}}},
  allow(['bedrock-agentcore:UpdateBrowserStream','bedrock-agentcore:StartBrowserSession','bedrock-agentcore:StopBrowserSession','bedrock-agentcore:ConnectBrowserAutomationStream','bedrock-agentcore:ConnectBrowserLiveViewStream'],att('Browser','BrowserArn'))
])]});
r.Controller=ready('AWS::Lambda::Function',{FunctionName:sub('${AWS::StackName}-controller'),Runtime:'nodejs24.x',Handler:'index.handler',MemorySize:512,Timeout:28,Role:att('ControllerRole'),Code:{S3Bucket:ref('Assets'),S3Key:ref('CodeKey')},Environment:{Variables:{RATE_TABLE:ref('RateTable'),BROWSER_ID:att('Browser','BrowserId'),SANDBOX_ENABLED:ref('Enabled'),ALLOWED_ORIGINS:{'Fn::Join':[',',ref('AllowedOrigins')]}}}});
r.Api=ready('AWS::ApiGatewayV2::Api',{Name:sub('${AWS::StackName}-api'),ProtocolType:'HTTP',CorsConfiguration:{AllowOrigins:ref('AllowedOrigins'),AllowMethods:['POST'],AllowHeaders:['content-type'],ExposeHeaders:['retry-after'],MaxAge:600}});
r.Integration=ready('AWS::ApiGatewayV2::Integration',{ApiId:ref('Api'),IntegrationType:'AWS_PROXY',IntegrationUri:att('Controller'),PayloadFormatVersion:'2.0',TimeoutInMillis:29000});
r.Route=ready('AWS::ApiGatewayV2::Route',{ApiId:ref('Api'),RouteKey:'POST /sandbox',Target:sub('integrations/${Integration}')});
r.Stage=ready('AWS::ApiGatewayV2::Stage',{ApiId:ref('Api'),StageName:'$default',AutoDeploy:true,DefaultRouteSettings:{ThrottlingBurstLimit:2,ThrottlingRateLimit:0.2}},{DependsOn:['Route']});
r.Permission=ready('AWS::Lambda::Permission',{Action:'lambda:InvokeFunction',FunctionName:ref('Controller'),Principal:'apigateway.amazonaws.com',SourceArn:sub('arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${Api}/*/POST/sandbox')});
t.Outputs={ArtifactBucket:{Value:ref('Assets')},Endpoint:{Condition:'Ready',Value:sub('https://${Api}.execute-api.${AWS::Region}.amazonaws.com/sandbox')},BrowserId:{Condition:'Ready',Value:att('Browser','BrowserId')},ControllerName:{Condition:'Ready',Value:ref('Controller')},RateTableName:{Condition:'Ready',Value:ref('RateTable')}};

await writeFile('infra/captcha-cloudformation.json',JSON.stringify(t,null,2)+'\n');
console.log('Prepared isolated sandbox stack. Empty CodeKey creates only its private artifact bucket.');

