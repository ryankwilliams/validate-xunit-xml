"""Module building xml validate xunit cli command."""
import glob
import logging
import os
import xml.etree.ElementTree
from copy import deepcopy
from typing import Any
from typing import Dict
from typing import List
from typing import Tuple
from xml.etree import ElementTree

import click
import pkg_resources
import xmlschema


logger = logging.getLogger(__name__)


class XunitValidate:
    """Handles validating xUnit result files (jUnit based) against jUnit schema
    and supports updating xUnit result files to be schema compliant."""

    def __init__(self, update: bool, overwrite: bool) -> None:
        """Constructs a XunitValidate object.

        :param update: determines whether the xml file should be fixed
            (when errors found)
        :param overwrite: determines whether the updated xml file should
            override the original file
        """
        self.update: bool = update
        self.overwrite: bool = overwrite
        self.schema: Dict[str, Any] = {}

        self.junit_xsd: xmlschema.XMLSchema = xmlschema.XMLSchema(
            pkg_resources.resource_filename(
                "validate_xunit_xml",
                "schemas/junit-10.xsd",
            ),
        )

        self.parse_schema()

    def parse_schema(self) -> None:
        """Extract components from the XSD schema using xmlschema for later usage.

        Stores the extracted schema components into the schema attribute.
        """
        key: str

        test_suite_element: xmlschema.XsdElement = self.junit_xsd.elements["testsuite"]
        test_suite_element_type: xmlschema.validators.XsdComplexType = (
            self.get_element_type(
                test_suite_element,
            )
        )

        if test_suite_element_type.has_complex_content():
            parent_element: xmlschema.XsdElement
            for parent_element in test_suite_element_type.content.iter_elements():
                if parent_element.tag != "testsuite":
                    continue

                parent_element_type = self.get_element_type(parent_element)
                if parent_element_type.has_complex_content():
                    self.schema[parent_element.tag] = {
                        "attributes": {"required": [], "optional": []},
                    }

                    for attribute in parent_element.attributes:
                        key = self.element_attribute_type(
                            parent_element,
                            attribute,
                        )
                        self.schema[parent_element.tag]["attributes"][key].append(
                            attribute,
                        )

                    child_element: xmlschema.XsdElement
                    for child_element in parent_element_type.content.iter_elements():
                        if child_element.tag == "testsuite":
                            continue
                        self.schema[parent_element.tag].update(
                            {
                                child_element.tag: {
                                    "attributes": {
                                        "required": [],
                                        "optional": [],
                                    },
                                },
                            },
                        )

                        for attribute in child_element.attributes:
                            key = self.element_attribute_type(
                                child_element,
                                attribute,
                            )
                            self.schema[parent_element.tag][child_element.tag][
                                "attributes"
                            ][key].append(
                                attribute,
                            )

                        child_element_type = self.get_element_type(
                            child_element,
                        )
                        if child_element_type.has_complex_content():
                            sub_child_element: xmlschema.XsdElement

                            for (
                                sub_child_element
                            ) in child_element_type.content.iter_elements():
                                self.schema[parent_element.tag][
                                    child_element.tag
                                ].update(
                                    {
                                        sub_child_element.tag: {
                                            "attributes": {
                                                "required": [],
                                                "optional": [],
                                            },
                                        },
                                    },
                                )
                                for attribute in sub_child_element.attributes:
                                    key = self.element_attribute_type(
                                        sub_child_element,
                                        attribute,
                                    )
                                    self.schema[parent_element.tag][child_element.tag][
                                        sub_child_element.tag
                                    ]["attributes"][key].append(attribute)

    @staticmethod
    def element_attribute_type(
        element: xmlschema.XsdElement,
        attribute_name: str,
    ) -> str:
        """Determines if the elements attribute is a required or optional attribute.

        :param element: the xsd element
        :param attribute_name: the attribute name to check for
        :return: whether the attribute is required or optional
        """
        attribute_type: str = "optional"
        if element.attributes[attribute_name].use == "required":
            attribute_type = "required"
        return attribute_type

    @staticmethod
    def get_element_type(
        element: xmlschema.XsdElement,
    ) -> xmlschema.validators.XsdComplexType:
        """Get the xsd element type.

        :param element: the xsd element
        :return: the xsd element type object
        """
        return getattr(element, "type")

    def schema_check(self, xml_file: str) -> Dict[str, bool]:
        """Validate the xml file against the XSD schema and log errors that were found.

        :param xml_file: the xml filename to validate
        :return: xml is schema compliant and xml is parsable
        """
        valid: bool = True
        parsable: bool = True
        error: xmlschema.XMLSchemaValidationError

        try:
            if not self.junit_xsd.is_valid(xml_file):
                logger.debug("Errors:")
                for error in self.junit_xsd.iter_errors(xml_file):
                    valid = False
                    logger.debug(
                        f"  Message: {error.message}\n  Reason: {error.reason}",
                    )
        except xml.etree.ElementTree.ParseError:
            logger.warning(
                f"  Unable to parse {xml_file}. Possibly an invalid XML?",
            )
            valid = False
            parsable = False
        return dict(schema_compliant=valid, parsable=parsable)

    def validate(self, xml_files: List[str]) -> None:
        """Validates a list of xml files against the schema file.

        :param xml_files: schema files to validate
        """
        index: int
        xml_file: str

        for index, xml_file in enumerate(xml_files, start=1):
            logger.info(f"{index}.\n  Filename: {xml_file}")
            result: Dict[str, bool] = self.schema_check(xml_file)
            if not result["schema_compliant"] and self.update:
                self.update_xml(xml_file)
            elif result["schema_compliant"]:
                logger.info(f"  XML: {xml_file} is schema compliant!")

    @staticmethod
    def required_attribute_check(
        element: xml.etree.ElementTree.Element,
        schema: Dict[str, Any],
    ) -> None:
        """Validate a elements attributes to ensure required ones are set (set when missing).

        :param element: xml element
        :param schema: the schema stating what attributes are valid
        """
        for req_attrib in schema["attributes"]["required"]:
            if req_attrib not in element.attrib:
                element.attrib[req_attrib] = ""
                continue

    @staticmethod
    def attribute_check(
        element: xml.etree.ElementTree.Element,
        schema: Dict[str, Any],
    ) -> None:
        """Validate a elements attributes and remove any that are not valid.

        :param element: xml element
        :param schema: the schema stating what attributes are valid
        """
        for attribute in deepcopy(element.attrib):
            if (
                attribute
                not in schema["attributes"]["required"]
                + schema["attributes"]["optional"]
            ):
                element.attrib.pop(attribute)

    def update_xml(self, xml_file: str) -> bool:
        """Update an xml file to be schema compliant.

        :param xml_file: schema file to update
        """
        xml_tree = ElementTree.parse(xml_file)
        xml_root = xml_tree.getroot()

        if xml_root.tag == "testsuites":
            test_suites = list(xml_root)
        elif xml_root.tag == "testsuite":
            test_suites = [xml_root]
        else:
            logger.warning(
                f"XML: {xml_file} is not compatible, missing testsuites or testsuite elements.",
            )
            return False

        logger.info(f"Updating {xml_file} to be schema compliant")

        for test_suite in test_suites:
            if test_suite.tag != "testsuite":
                xml_root.remove(test_suite)
                continue

            self.required_attribute_check(test_suite, self.schema["testsuite"])
            self.attribute_check(test_suite, self.schema["testsuite"])

            for element in list(test_suite):
                if element.tag not in self.schema["testsuite"]:
                    test_suite.remove(element)

                self.required_attribute_check(
                    element,
                    self.schema["testsuite"][element.tag],
                )
                self.attribute_check(
                    element,
                    self.schema["testsuite"][element.tag],
                )

                for child_element in list(element):
                    if child_element.tag not in self.schema["testsuite"][element.tag]:
                        element.remove(child_element)
                        continue

                    self.required_attribute_check(
                        child_element,
                        self.schema["testsuite"][element.tag][child_element.tag],
                    )
                    self.attribute_check(
                        child_element,
                        self.schema["testsuite"][element.tag][child_element.tag],
                    )

        filename: str = xml_file
        if not self.overwrite:
            _xml_file: Tuple[str, str] = os.path.splitext(xml_file)
            filename = f"{_xml_file[0]}_updated{_xml_file[1]}"
        xml_tree.write(filename)

        logger.info(
            f"XML: {xml_file} is now schema compliant. Updated XML: {filename}",
        )
        return True


def initialize_logger(verbose: bool) -> None:
    """Initialize logger configuration.

    :param verbose: toggles whether debug logging is enabled
    """
    log_level: int
    log_format: str

    if verbose:
        log_level = logging.DEBUG
        log_format = "%(asctime)s %(name)s.%(funcName)s:%(lineno)d : %(message)s"
    else:
        log_level = logging.INFO
        log_format = "%(asctime)s : %(message)s"

    logging.basicConfig(format=log_format, level=log_level)


@click.option(
    "--xml-path",
    required=True,
    multiple=True,
    help="XML filename or directory containing xml files",
)
@click.option(
    "--update",
    is_flag=True,
    default=False,
    help="Updates an invalid XML to be schema compliant",
)
@click.option(
    "--overwrite",
    is_flag=True,
    default=False,
    help="Overwrite original xml file (goes with --update)",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    default=False,
    help="Enable verbose mode",
)
@click.command("validate-xunit", short_help="Validate xUnit xml files")
@click.pass_context
def cli(
    ctx: click.Context,
    xml_path: str,
    update: bool,
    overwrite: bool,
    verbose: bool,
) -> None:
    """Validate xUnit files against xsd schema and update to be schema compliant.

    \b
    Examples
      # Validate a individual xUnit xml
      $ validate-xunit-xml --xml-path tests-1.xml
      \b
      # Validate a individual xUnit xml and a directory of xUnit xmls
      $ validate-xunit-xml --xml-path tests-1.xml --xml-path xml-dirs
      \b
      # Validate a individual xUnit xml and update it to be schema compliant
      $ validate-xunit-xml --xml-path tests-1.xml --update
      \b
    """
    initialize_logger(verbose)

    xml_files: List[str] = list()
    for item in xml_path:
        if os.path.isfile(item):
            xml_files.append(item)
            continue
        if os.path.isdir(item):
            xml_files += glob.glob(f"{item}/**/*.xml", recursive=True)
            continue

    if len(xml_files) == 0:
        logger.error(
            "No valid XML files found. Please verify your paths and try again.",
        )
        raise SystemExit(1)

    xunit_validate = XunitValidate(update, overwrite)
    xunit_validate.validate(xml_files)
