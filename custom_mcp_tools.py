from typing import Any
import httpx
from mcp.server.fastmcp import FastMCP
from datetime import datetime
import random
import re
import os
# Initialize FastMCP server
mcp = FastMCP("custom_mcp_tools ")


@mcp.tool()
async def get_office_jokes() -> str:
    """Get office jokes
    """
    # List of office jokes
    jokes = ["Why don't scientists trust atoms? Because they make up everything!",
    "Why did the scarecrow become a successful motivational speaker? Because he was outstanding in his field!",
    "Why don't skeletons fight each other? They don't have the guts.",
    "Why did the bicycle fall over? It was two-tired!","Why did the math book look sad? Because it had too many problems."
    ]

    return random.choice(jokes)


@mcp.tool()
async def get_current_date() -> str:
    """Get current date
    """
    return str(datetime.today().strftime('%Y-%m-%d'))


@mcp.tool()
async def get_github_repo_files(repo_url: str, branch: str = "HEAD", trigger_from_chat: bool = False) -> list[str]:
    """Given a GitHub repository URL and branch, return a list of all file paths in the repo. If trigger_from_chat is True, print a message for Copilot Chat."""
    # Extract owner and repo from URL
    match = re.match(r"https://github.com/([^/]+)/([^/.]+)(?:.git)?", repo_url)
    if not match:
        return ["Invalid GitHub repository URL."]
    owner, repo = match.group(1), match.group(2)

    api_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    headers = {"Accept": "application/vnd.github.v3+json"}
    async with httpx.AsyncClient() as client:
        resp = await client.get(api_url, headers=headers)
        if resp.status_code != 200:
            return [f"Failed to fetch repo files: {resp.status_code}"]
        data = resp.json()
        files = [item['path'] for item in data.get('tree', []) if item['type'] == 'blob']
        if trigger_from_chat:
            print(f"[Copilot Chat] Listed {len(files)} files from {repo_url} (branch: {branch})")
        return files


@mcp.tool()
async def generate_openapi_specification_from_repo(repo_url: str, dest_dir: str = None) -> str:
    """
    Generate comprehensive OpenAPI 3.1.0 specification with dummy values for missing attributes.
    Ensures complete documentation by adding default values per OpenAPI standards.
    """
    import subprocess
    import tempfile
    import os
    import yaml
    import json
    import glob
    import re
    import ast
    import logging
    import shutil
    from datetime import datetime
    from pathlib import Path
    from typing import Dict, List, Any, Optional

    # Setup logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("enhanced-openapi-generator")

    class OpenAPISpecCleaner:
        """Handles cleanup of existing OpenAPI specifications"""
        
        @staticmethod
        def cleanup_specs(workspace_dir: str) -> None:
            """Remove all existing OpenAPI specification files"""
            patterns = ['openapi*.yaml', 'openapi*.yml']
            for pattern in patterns:
                for spec_file in glob.glob(os.path.join(workspace_dir, pattern)):
                    try:
                        os.remove(spec_file)
                        logger.info(f"Removed existing YAML spec file: {spec_file}")
                    except Exception as e:
                        logger.warning(f"Failed to remove YAML spec file {spec_file}: {str(e)}")

    class JavaSpringParser:
        """Enhanced parser for Java Spring controllers and models"""
        
        @staticmethod
        def parse_controller(content: str) -> Dict[str, Any]:
            """Parse Spring Controller class with enhanced detection"""
            result = {
                "base_path": "",
                "endpoints": [],
                "tag": "",
                "description": ""
            }

            # Extract class level annotations
            class_match = re.search(r'@RestController\s+(?:@RequestMapping\(["\']([^"\']+)["\']\))?\s*public\s+class\s+(\w+)', content)
            if class_match:
                result["base_path"] = class_match.group(1) or ""
                result["tag"] = class_match.group(2).replace("Controller", "")
                result["description"] = f"Operations related to {result['tag']}"

            # Extract all endpoint methods with enhanced pattern matching
            endpoint_pattern = r'@(?:Get|Post|Put|Patch|Delete)Mapping\s*(?:\([^)]*\))?\s*(?:public|private)\s+(?:ResponseEntity<)?(\w+(?:<[^>]+>)?)\s*>?\s*(\w+)\s*\(([^)]*)\)'
            for match in re.finditer(endpoint_pattern, content, re.DOTALL):
                return_type, method_name, params = match.groups()
                
                # Extract HTTP method and path
                method_match = re.search(r'@(?:Get|Post|Put|Patch|Delete)Mapping\s*(?:\([^)]*\))?', match.group(0))
                http_method = method_match.group(1).lower() if method_match else "get"
                
                # Extract path from mapping annotation
                path_match = re.search(r'@\w+Mapping\s*\(\s*["\']([^"\']+)["\']', match.group(0))
                path = path_match.group(1) if path_match else "/"
                
                endpoint = {
                    "path": path,
                    "method": http_method,
                    "operation_id": method_name,
                    "summary": JavaSpringParser.generate_summary(method_name, http_method),
                    "description": JavaSpringParser.generate_description(method_name, http_method),
                    "parameters": JavaSpringParser.parse_parameters(params),
                    "return_type": return_type,
                    "responses": JavaSpringParser.generate_responses(return_type)
                }
                
                result["endpoints"].append(endpoint)

            return result

        @staticmethod
        def generate_summary(method_name: str, http_method: str) -> str:
            """Generate meaningful operation summaries"""
            action_map = {
                "get": "Retrieve",
                "post": "Create",
                "put": "Update",
                "patch": "Partially update",
                "delete": "Delete"
            }
            
            base_action = action_map.get(http_method, "Process")
            resource = re.sub(r'(get|create|update|delete|find|modify)', '', method_name)
            resource = re.sub(r'([A-Z])', r' \1', resource).strip()
            
            if "ById" in method_name or "ByName" in method_name:
                return f"{base_action} {resource} by identifier"
            elif "All" in method_name:
                return f"{base_action} all {resource}s"
            else:
                return f"{base_action} {resource}"

        @staticmethod
        def generate_description(method_name: str, http_method: str) -> str:
            """Generate detailed operation descriptions"""
            summary = JavaSpringParser.generate_summary(method_name, http_method)
            return f"{summary}. This endpoint supports {http_method.upper()} operations for the resource."

        @staticmethod
        def parse_parameters(params_str: str) -> List[Dict[str, Any]]:
            """Parse method parameters with enhanced type detection"""
            parameters = []
            for param in params_str.split(','):
                param = param.strip()
                if not param:
                    continue

                param_match = re.match(r'(?:@(\w+)\s+)?(\w+(?:<.*?>)?)\s+(\w+)', param)
                if param_match:
                    annotation, param_type, param_name = param_match.groups()
                    param_info = {
                        "name": param_name,
                        "in": "query",  # default location
                        "required": False,
                        "schema": JavaSpringParser.get_parameter_schema(param_type),
                        "description": f"Parameter {param_name} of type {param_type}"
                    }

                    # Update parameter location and requirements based on annotation
                    if annotation == "PathVariable":
                        param_info["in"] = "path"
                        param_info["required"] = True
                    elif annotation == "RequestParam":
                        param_info["in"] = "query"
                    elif annotation == "RequestBody":
                        param_info = {
                            "in": "body",
                            "name": "body",
                            "required": True,
                            "schema": {"$ref": f"#/components/schemas/{param_type}"},
                            "description": f"Request body of type {param_type}"
                        }

                    parameters.append(param_info)

            return parameters

        @staticmethod
        def get_parameter_schema(param_type: str) -> Dict[str, Any]:
            """Generate parameter schema with type mapping"""
            type_mapping = {
                "String": {"type": "string"},
                "Integer": {"type": "integer", "format": "int32"},
                "Long": {"type": "integer", "format": "int64"},
                "Boolean": {"type": "boolean"},
                "Float": {"type": "number", "format": "float"},
                "Double": {"type": "number", "format": "double"},
                "LocalDate": {"type": "string", "format": "date"},
                "LocalDateTime": {"type": "string", "format": "date-time"},
                "UUID": {"type": "string", "format": "uuid"}
            }

            if param_type in type_mapping:
                return type_mapping[param_type]
            else:
                return {"type": "string"}  # default to string for unknown types

        @staticmethod
        def generate_responses(return_type: str) -> Dict[str, Any]:
            """Generate comprehensive response documentation"""
            is_collection = "List<" in return_type or "[]" in return_type
            base_type = return_type.replace("List<", "").replace(">", "").replace("[]", "").replace("ResponseEntity<", "")
            
            schema = {
                "$ref": f"#/components/schemas/{base_type}"
            } if not is_collection else {
                "type": "array",
                "items": {"$ref": f"#/components/schemas/{base_type}"}
            }

            return {
                "200": {
                    "description": "Successful operation",
                    "content": {
                        "application/json": {
                            "schema": schema
                        }
                    }
                },
                "400": {
                    "description": "Bad request",
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/ErrorResponse"}
                        }
                    }
                },
                "401": {
                    "description": "Unauthorized",
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/ErrorResponse"}
                        }
                    }
                },
                "404": {
                    "description": "Not found",
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/ErrorResponse"}
                        }
                    }
                }
            }

    # Define workspace paths
    workspace_dir = os.path.dirname(os.path.abspath(__file__))
    openapi_filename = "openapi.generated.yaml"
    workspace_output_path = os.path.join(workspace_dir, openapi_filename)

    # Clean up existing specs
    OpenAPISpecCleaner.cleanup_specs(workspace_dir)
    logger.info("Cleaned up existing OpenAPI specifications")

    # Create temp directory if needed
    if dest_dir is None:
        dest_dir = tempfile.mkdtemp(prefix="openapi_gen_")
    
    try:
        # Clone repository
        logger.info(f"Cloning repository: {repo_url}")
        result = subprocess.run(["git", "clone", repo_url, dest_dir], capture_output=True, text=True, check=True)

        # Initialize spec structure
        openapi_spec = {
            "openapi": "3.1.0",
            "info": {
                "title": "Hackathon API",
                "version": datetime.now().strftime("%Y.%m.%d"),
                "description": "Comprehensive API documentation for the Hackathon project",
                "termsOfService": "https://example.com/terms",
                "contact": {
                    "name": "API Support Team",
                    "email": "api-support@example.com",
                    "url": "https://example.com/support"
                },
                "license": {
                    "name": "MIT License",
                    "url": "https://opensource.org/licenses/MIT",
                    "identifier": "MIT"
                }
            },
            "servers": [
                {
                    "url": "http://localhost:8080",
                    "description": "Local development server"
                },
                {
                    "url": "https://api-staging.example.com",
                    "description": "Staging environment"
                },
                {
                    "url": "https://api.example.com",
                    "description": "Production environment"
                }
            ],
            "paths": {},
            "components": {
                "schemas": {},
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    }
                }
            },
            "security": [{"bearerAuth": []}],
            "tags": []
        }

        # Process all controllers
        logger.info("Processing controllers...")
        controller_pattern = os.path.join(dest_dir, "**/*Controller.java")
        for controller_file in glob.glob(controller_pattern, recursive=True):
            with open(controller_file, 'r') as f:
                content = f.read()
                controller_info = JavaSpringParser.parse_controller(content)
                
                # Add tag if not exists
                if not any(tag["name"] == controller_info["tag"] for tag in openapi_spec["tags"]):
                    openapi_spec["tags"].append({
                        "name": controller_info["tag"],
                        "description": controller_info["description"]
                    })
                
                # Process endpoints
                for endpoint in controller_info["endpoints"]:
                    full_path = (controller_info["base_path"] + endpoint["path"]).replace("//", "/")
                    
                    if full_path not in openapi_spec["paths"]:
                        openapi_spec["paths"][full_path] = {}
                    
                    openapi_spec["paths"][full_path][endpoint["method"]] = {
                        "tags": [controller_info["tag"]],
                        "summary": endpoint["summary"],
                        "description": endpoint["description"],
                        "operationId": endpoint["operation_id"],
                        "parameters": endpoint["parameters"],
                        "responses": endpoint["responses"]
                    }

        # Process all response models
        logger.info("Processing response models...")
        model_pattern = os.path.join(dest_dir, "**/*Response.java")
        for model_file in glob.glob(model_pattern, recursive=True):
            with open(model_file, 'r') as f:
                content = f.read()
                class_match = re.search(r'class\s+(\w+)', content)
                if class_match:
                    class_name = class_match.group(1)
                    fields = re.finditer(r'private\s+(\w+(?:<.*?>)?)\s+(\w+);', content)
                    
                    properties = {}
                    for field in fields:
                        field_type, field_name = field.groups()
                        properties[field_name] = JavaSpringParser.get_parameter_schema(field_type)
                        properties[field_name]["description"] = f"The {field_name} of the {class_name}"
                    
                    openapi_spec["components"]["schemas"][class_name] = {
                        "type": "object",
                        "description": f"Represents a {class_name} entity",
                        "properties": properties
                    }

        # Add standard error response
        openapi_spec["components"]["schemas"]["ErrorResponse"] = {
            "type": "object",
            "description": "Standard error response",
            "required": ["code", "message"],
            "properties": {
                "code": {"type": "string", "example": "ERR-001"},
                "message": {"type": "string", "example": "Error message"},
                "details": {"type": "object", "description": "Additional error details"}
            }
        }

        # Write to temporary location first
        temp_output_path = os.path.join(dest_dir, openapi_filename)
        logger.info(f"Writing OpenAPI specification to temporary location: {temp_output_path}")
        with open(temp_output_path, "w") as f:
            yaml.dump(openapi_spec, f, sort_keys=False, default_flow_style=False)

        # Copy to workspace
        shutil.copy2(temp_output_path, workspace_output_path)
        logger.info(f"Copied OpenAPI specification to workspace: {workspace_output_path}")

        # Clean up temp directory
        shutil.rmtree(dest_dir)
        logger.info("Cleaned up temporary directory")

        return f"OpenAPI specification generated successfully at {workspace_output_path}"

    except Exception as e:
        logger.error(f"Error generating OpenAPI specification: {str(e)}")
        if os.path.exists(dest_dir):
            shutil.rmtree(dest_dir)
        return f"Failed to generate OpenAPI specification: {str(e)}"


@mcp.tool()
async def validate_openapi_policy(spec_path: str) -> str:
    """
    Validates an OpenAPI specification against predefined quality and compliance policies.
    
    Args:
        spec_path (str): Path to the OpenAPI specification file
        
    Returns:
        str: Validation report
    """
    import yaml
    import json
    import re
    from typing import Dict, List, Any

    class OpenAPIValidator:
        def __init__(self):
            self.violations = []
            self.warnings = []
            self.passed = []

        def validate_info_section(self, info: Dict[str, Any]):
            required_fields = ["title", "version", "description"]
            recommended_fields = ["contact", "license"]
            
            for field in required_fields:
                if field not in info:
                    self.violations.append(f"Required field '{field}' missing in info section")
                else:
                    self.passed.append(f"Info section contains required field '{field}'")
            
            for field in recommended_fields:
                if field not in info:
                    self.warnings.append(f"Recommended field '{field}' missing in info section")
                else:
                    self.passed.append(f"Info section contains recommended field '{field}'")

        def validate_security(self, spec: Dict[str, Any]):
            if "security" not in spec:
                self.violations.append("No security requirements defined")
            elif "securitySchemes" not in spec.get("components", {}):
                self.violations.append("Security schemes not defined in components")
            else:
                self.passed.append("Security requirements properly defined")

        def validate_responses(self, paths: Dict[str, Any]):
            for path, methods in paths.items():
                for method, operation in methods.items():
                    if "responses" not in operation:
                        self.violations.append(f"No responses defined for {method.upper()} {path}")
                        continue
                    
                    responses = operation["responses"]
                    if "200" not in responses and "201" not in responses:
                        self.warnings.append(f"No success response (200/201) defined for {method.upper()} {path}")
                    
                    if "400" not in responses:
                        self.warnings.append(f"No bad request (400) response defined for {method.upper()} {path}")
                    
                    if "401" not in responses and "403" not in responses:
                        self.warnings.append(f"No authorization (401/403) response defined for {method.upper()} {path}")
                    
                    self.passed.append(f"Response definitions present for {method.upper()} {path}")

        def validate_parameters(self, paths: Dict[str, Any]):
            for path, methods in paths.items():
                for method, operation in methods.items():
                    if "parameters" in operation:
                        for param in operation["parameters"]:
                            if "description" not in param:
                                self.warnings.append(f"Parameter '{param.get('name', 'unknown')}' missing description in {method.upper()} {path}")
                            if "schema" not in param:
                                self.violations.append(f"Parameter '{param.get('name', 'unknown')}' missing schema in {method.upper()} {path}")
                            else:
                                self.passed.append(f"Parameter '{param.get('name', 'unknown')}' properly documented in {method.upper()} {path}")

        def validate_naming_conventions(self, paths: Dict[str, Any]):
            for path in paths.keys():
                if not path.startswith('/'):
                    self.violations.append(f"Path '{path}' does not start with /")
                if '//' in path:
                    self.violations.append(f"Path '{path}' contains double slashes")
                if re.search(r'[A-Z]', path):
                    self.warnings.append(f"Path '{path}' contains uppercase letters, should be lowercase")
                else:
                    self.passed.append(f"Path '{path}' follows naming conventions")

        def get_report(self) -> str:
            total_checks = len(self.passed) + len(self.violations) + len(self.warnings)
            report = [
                "OpenAPI Specification Validation Report",
                "=====================================",
                f"Total Checks: {total_checks}",
                f"Passed: {len(self.passed)}",
                f"Violations (Must Fix): {len(self.violations)}",
                f"Warnings (Should Fix): {len(self.warnings)}",
                "",
                "Violations:",
                "----------"
            ]
            report.extend([f"- {v}" for v in self.violations])
            report.extend([
                "",
                "Warnings:",
                "--------"
            ])
            report.extend([f"- {w}" for w in self.warnings])
            report.extend([
                "",
                "Passed Checks:",
                "-------------"
            ])
            report.extend([f"- {p}" for p in self.passed])
            
            return "\n".join(report)

    # Read the OpenAPI specification
    with open(spec_path, 'r') as f:
        spec = yaml.safe_load(f)

    # Initialize validator
    validator = OpenAPIValidator()

    # Run validations
    validator.validate_info_section(spec.get("info", {}))
    validator.validate_security(spec)
    validator.validate_responses(spec.get("paths", {}))
    validator.validate_parameters(spec.get("paths", {}))
    validator.validate_naming_conventions(spec.get("paths", {}))

    return validator.get_report()


@mcp.tool()
async def publish_openapi_to_readme(api_spec_path: str, api_key: str = "") -> str:
    """
    Publish OpenAPI specification to readme.io developer portal.
    
    Args:
        api_spec_path (str): Path to the OpenAPI specification file (YAML)
        api_key (str): readme.io API key for authentication
        
    Returns:
        str: Success/failure message with details
    """
    import httpx
    import yaml
    import logging
    from pathlib import Path
    import base64

    # Setup logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("readme-publisher")

    try:
        # Validate file exists and is YAML
        spec_path = Path(api_spec_path)
        if not spec_path.exists():
            return f"Error: OpenAPI specification file not found at {api_spec_path}"
        
        if not api_spec_path.endswith(('.yaml', '.yml')):
            return "Error: File must be a YAML OpenAPI specification"

        # Read the OpenAPI spec as binary
        logger.info(f"Reading OpenAPI specification from {api_spec_path}")
        with open(spec_path, 'rb') as f:
            spec_content = f.read()

        # readme.com API endpoint
        api_url = "https://dash.readme.com/api/v1/api-specification"
        
        # Create proper Basic Auth header
        encoded_auth = base64.b64encode(f"{api_key}:".encode()).decode()
        
        headers = {
            "Accept": "application/json",
            "Authorization": f"Basic {encoded_auth}"
        }

        # Prepare multipart form data
        files = {
            'spec': ('openapi.yaml', spec_content, 'application/x-yaml')
        }

        # Upload spec to readme.com
        logger.info("Publishing specification to readme.com")
        async with httpx.AsyncClient() as client:
            response = await client.post(
                api_url,
                headers=headers,
                files=files,
                timeout=30.0  # Set explicit timeout
            )

            logger.info(f"Response status: {response.status_code}")
            logger.info(f"Response headers: {response.headers}")
            
            try:
                response_data = response.json()
                logger.info(f"Response body: {response_data}")
            except Exception as e:
                logger.error(f"Failed to parse response as JSON: {str(e)}")
                response_data = {}

            if response.status_code in [200, 201]:
                logger.info("Successfully published OpenAPI specification to readme.com")
                return f"Successfully published API specification to readme.com. ID: {response_data.get('id', 'N/A')}"
            else:
                error_msg = response_data.get('message', response_data.get('error', 'Unknown error'))
                logger.error(f"Failed to publish specification: {error_msg}")
                return f"Error publishing to readme.com: {error_msg} (Status: {response.status_code})"

    except Exception as e:
        logger.error(f"Error during publication: {str(e)}")
        return f"Error: {str(e)}"


if __name__ == "__main__":
    # Initialize and run the server
    mcp.run(transport='stdio')