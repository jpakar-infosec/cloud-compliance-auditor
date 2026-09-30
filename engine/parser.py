"""
Terraform HCL Parser for GRC Compliance Engine.
Extracts resources, blocks, and attributes without external dependencies.
"""

import os
import re
from typing import Dict, List, Any


class TerraformResource:
    def __init__(self, resource_type: str, resource_name: str, file_path: str, line_number: int):
        self.resource_type = resource_type
        self.resource_name = resource_name
        self.file_path = file_path
        self.line_number = line_number
        self.attributes: Dict[str, Any] = {}
        self.blocks: Dict[str, List[Dict[str, Any]]] = {}
        self.raw_text: str = ""

    def __repr__(self):
        return f"<Resource {self.resource_type}.{self.resource_name} ({os.path.basename(self.file_path)}:{self.line_number})>"


class TerraformParser:
    """Lightweight parser for Terraform resource blocks."""

    @staticmethod
    def parse_directory(directory_path: str) -> List[TerraformResource]:
        """Scans all .tf files in a directory and returns parsed resources."""
        resources: List[TerraformResource] = []
        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        for root, _, files in os.walk(directory_path):
            for file in sorted(files):
                if file.endswith(".tf"):
                    full_path = os.path.join(root, file)
                    resources.extend(TerraformParser.parse_file(full_path))
        return resources

    @staticmethod
    def parse_file(file_path: str) -> List[TerraformResource]:
        """Parses a single .tf file into resource objects."""
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        return TerraformParser.parse_content(content, file_path)

    @staticmethod
    def parse_content(content: str, file_path: str = "<memory>") -> List[TerraformResource]:
        """Extracts resources and their attributes from text."""
        resources: List[TerraformResource] = []
        
        # Regex to locate top-level resource blocks: resource "type" "name" {
        pattern = re.compile(
            r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{',
            re.MULTILINE
        )

        lines = content.splitlines()

        for match in pattern.finditer(content):
            res_type = match.group(1)
            res_name = match.group(2)
            start_pos = match.end() - 1  # starting at '{'
            
            # Find line number
            line_no = content[:match.start()].count("\n") + 1

            # Match balanced braces to isolate the resource body
            brace_count = 0
            end_pos = start_pos
            for i in range(start_pos, len(content)):
                if content[i] == '{':
                    brace_count += 1
                elif content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i + 1
                        break
            
            body = content[start_pos + 1 : end_pos - 1]
            resource = TerraformResource(res_type, res_name, file_path, line_no)
            resource.raw_text = content[match.start() : end_pos]
            TerraformParser._parse_body(body, resource)
            resources.append(resource)

        return resources

    @staticmethod
    def _parse_body(body: str, resource: TerraformResource):
        """Extracts simple key-value attributes and nested blocks."""
        # Find sub-blocks like ingress { ... }, egress { ... }, rule { ... }
        block_pattern = re.compile(r'([a-zA-Z0-9_\-]+)\s*\{')
        i = 0
        cleaned_body_parts = []
        last_idx = 0

        while i < len(body):
            match = block_pattern.search(body, i)
            if not match:
                cleaned_body_parts.append(body[last_idx:])
                break

            block_name = match.group(1)
            brace_start = match.end() - 1
            cleaned_body_parts.append(body[last_idx:match.start()])

            # Balance braces for the subblock
            brace_count = 0
            sub_end = brace_start
            for j in range(brace_start, len(body)):
                if body[j] == '{':
                    brace_count += 1
                elif body[j] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        sub_end = j + 1
                        break

            sub_body = body[brace_start + 1 : sub_end - 1]
            sub_res = TerraformResource(block_name, "", resource.file_path, resource.line_number)
            TerraformParser._parse_body(sub_body, sub_res)
            
            if block_name not in resource.blocks:
                resource.blocks[block_name] = []
            
            # Combine attributes of subblock
            combined_dict = dict(sub_res.attributes)
            if sub_res.blocks:
                combined_dict["_nested_blocks"] = sub_res.blocks
            resource.blocks[block_name].append(combined_dict)

            last_idx = sub_end
            i = sub_end

        # Now parse remaining top-level key-values from cleaned text
        cleaned_text = "".join(cleaned_body_parts)
        for line in cleaned_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            if "=" in line:
                k, v = line.split("=", 1)
                key = k.strip()
                val = v.strip().rstrip(",")
                resource.attributes[key] = TerraformParser._clean_value(val)

    @staticmethod
    def _clean_value(val: str) -> Any:
        """Parses strings, booleans, numbers, and lists from Terraform string values."""
        val = val.strip()
        if val == "true":
            return True
        if val == "false":
            return False
        if val.isdigit():
            return int(val)
        if val.startswith('"') and val.endswith('"') and len(val) >= 2:
            return val[1:-1]
        if val.startswith("[") and val.endswith("]"):
            inner = val[1:-1].strip()
            if not inner:
                return []
            items = [TerraformParser._clean_value(x.strip()) for x in inner.split(",") if x.strip()]
            return items
        return val
